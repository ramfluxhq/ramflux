// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

import Foundation

/// The M3 acceptance driver. Not product UI: it runs one phase, writes a result file into
/// the app container's Documents directory and exits.
///
/// Phases (launch argument `--phase <name>`):
///
///   create-send   start the core, add the local gateway's node, create an account, send a
///                 direct message, then wait to be killed (the script sends SIGKILL)
///   restart       start again after the kill, unlock, prove the first message is still
///                 there and send a second one over the resumed session
///   suspend       suspend the core, assert the store is closed and the lock file is
///                 unlocked, wait while the script stops the process and probes the lock from
///                 outside, then resume, assert the lock is held again and send once more
///   background    follow the real application lifecycle notifications and record the
///                 evidence of each suspension (the script backgrounds the app)
///
/// The scenario (`Documents/scenario.json`) carries the request bodies and the peer.
final class Driver: @unchecked Sendable {
    let documents: URL
    let host: RamfluxHost
    let scenario: Scenario
    var variables: [String: String]
    var failures: [String] = []
    var notes: [String: String] = [:]

    init() throws {
        documents = try FileManager.default.url(
            for: .documentDirectory, in: .userDomainMask, appropriateFor: nil, create: true)
        let data = try Data(contentsOf: documents.appendingPathComponent("scenario.json"))
        scenario = try JSONDecoder().decode(Scenario.self, from: data)
        variables = scenario.variables ?? [:]
        // Variables saved by an earlier phase (the account id survives the kill on disk).
        let saved = documents.appendingPathComponent("variables.json")
        if let data = try? Data(contentsOf: saved),
            let earlier = try? JSONDecoder().decode([String: String].self, from: data)
        {
            variables.merge(earlier) { _, new in new }
        }
        host = try RamfluxHost()
    }

    // MARK: Phases

    func run(phase: String) async {
        do {
            switch phase {
            case "create-send": try await createAndSend()
            case "restart": try await restart()
            case "suspend": try await suspendCycle()
            case "background": try await backgroundCycle()
            default: fail("unknown phase \(phase)")
            }
        } catch {
            fail("\(phase): \(error)")
        }
        finish(phase: phase)
    }

    private func createAndSend() async throws {
        try await host.start()
        check(try LockProbe.state(dataRoot: host.dataRoot) == .held, "lock held while running")
        try await run(steps: scenario.setup)

        let ceremony = try await host.core.beginAccountCreation(
            displayName: scenario.displayName, nodeId: variables["node_id"])
        // The phrase is shown once. A product shows it to the user; the driver answers the
        // hidden challenge from it and lets it go out of scope.
        let phrase = try await ceremony.showOnce()
        let words = phrase.split(separator: " ").map(String.init)
        let positions = try await ceremony.hiddenChallenge()
        let answers = positions.map { position -> String in
            let index = Int(position) - 1
            return words.indices.contains(index) ? words[index] : ""
        }
        let created = try await ceremony.confirm(words: answers, passphrase: scenario.passphrase)
        variables["account_id"] = created.accountId
        notes["account_state"] = created.state
        notes["account_networking"] = created.networking
        try saveVariables()

        try await run(steps: scenario.afterCreate)
        try saveVariables()

        // Durable point reached. Publish the result first, then tell the script it may kill.
        finish(phase: "create-send")
        try Data("ready".utf8).write(to: documents.appendingPathComponent("ready-to-kill"))
        // Stay alive with the store open and the lock held: the kill must be abrupt.
        while true {
            try await Task.sleep(nanoseconds: 1_000_000_000)
        }
    }

    private func restart() async throws {
        guard variables["account_id"] != nil else {
            fail("no account from the create-send phase")
            return
        }
        // The killed process held the lock. The lock died with it; start must succeed.
        try await host.start()
        try await unlock()
        try await run(steps: scenario.afterRestart)
        try await host.close()
        check(try LockProbe.state(dataRoot: host.dataRoot) == .unlocked, "lock free after close")
    }

    private func suspendCycle() async throws {
        try await host.start()
        try await unlock()

        // A stream must end as suspended, not hang and not fail.
        let ended = Flag()
        let stream = try UpdateStream.open(
            on: host.core, account: variables["account_id"],
            topics: ["message.update"], apply: { _ in },
            end: { end in if end == .suspended { ended.set() } })

        let evidence = try await host.suspend()
        notes["suspend_elapsed_ms"] = String(evidence.elapsedMs)
        check(evidence.supervisorJoined, "supervisor thread joined")
        check(evidence.dataRootLockReleased, "core observed the released lock")
        check(host.core.state() == .suspended, "state is suspended")
        check(
            try LockProbe.state(dataRoot: host.dataRoot) == .unlocked,
            "fresh descriptor takes the data-root lock at suspension")
        let logs = LockProbe.nonEmptyWriteAheadLogs(dataRoot: host.dataRoot)
        check(logs.isEmpty, "no write-ahead data at suspension (found \(logs))")
        let streamEnded = await ended.wait(seconds: 5)
        check(streamEnded, "stream ended as suspended")
        stream.cancel()

        // A request while suspended is refused before admission: no effect, no hang.
        do {
            _ = try await host.core.run(
                try CoreRequest.json("account.list", deadlineMs: 2_000))
            fail("a request while suspended was admitted")
        } catch {
            notes["suspended_request"] = "refused"
        }

        // Hand over to the script: it stops this process (SIGSTOP), takes and releases the
        // lock from outside, continues the process and writes the marker.
        try Data(host.dataRoot.path.utf8).write(
            to: documents.appendingPathComponent("suspended"))
        let marker = documents.appendingPathComponent("continue")
        var waited = 0
        while !FileManager.default.fileExists(atPath: marker.path) {
            try await Task.sleep(nanoseconds: 100_000_000)
            waited += 1
            if waited > 1_200 {
                fail("the script never wrote the continue marker")
                return
            }
        }

        try await host.resume()
        check(host.core.state() == .running, "state is running after resume")
        check(
            try LockProbe.state(dataRoot: host.dataRoot) == .held,
            "data-root lock is held again after resume")
        try await unlock()
        try await run(steps: scenario.afterResume)
        try await host.close()
    }

    private func backgroundCycle() async throws {
        try await host.start()
        try await unlock()
        let driver = self
        await MainActor.run {
            host.followApplicationLifecycle { error in
                driver.fail("lifecycle: \(error)")
            }
        }
        // The script backgrounds the app, waits, foregrounds it and writes the marker.
        let marker = documents.appendingPathComponent("continue")
        var sawSuspended = false
        var waited = 0
        while !FileManager.default.fileExists(atPath: marker.path) {
            if host.core.state() == .suspended, !sawSuspended {
                sawSuspended = true
                check(
                    try LockProbe.state(dataRoot: host.dataRoot) == .unlocked,
                    "lock unlocked after didEnterBackground")
                try Data("suspended".utf8).write(
                    to: documents.appendingPathComponent("suspended"))
            }
            try await Task.sleep(nanoseconds: 100_000_000)
            waited += 1
            if waited > 1_200 { break }
        }
        check(sawSuspended, "the core suspended when the app entered the background")
        check(host.core.state() == .running, "the core resumed on return to the foreground")
        try await run(steps: scenario.afterResume)
        try await host.close()
    }

    // MARK: Steps

    private func unlock() async throws {
        let request = try CoreRequest.json(
            "account.unlock", account: variables["account_id"],
            body: ["passphrase": scenario.passphrase], deadlineMs: 60_000,
            operationId: "harness-unlock-\(UUID().uuidString.lowercased())")
        _ = try await host.core.reply(to: request)
    }

    private func run(steps: [Scenario.Step]) async throws {
        for step in steps {
            let body = try step.body?.resolved(variables) as? [String: Any] ?? [:]
            let account = try step.account.map { try substitute($0, variables) }
            let operation = try step.operationId.map { try substitute($0, variables) }
            let request = try CoreRequest.json(
                step.method, account: account, body: body,
                deadlineMs: step.deadlineMs ?? 60_000, operationId: operation)
            let reply: [String: Any]
            switch try await host.core.run(request) {
            case .completed(let response):
                reply = try response.object()
            case .endedBeforeClaim:
                throw ScenarioError.waitEnded(method: step.method, claimed: false)
            case .endedAfterClaim:
                // Unknown effect. The driver does not resend: a resend with a new key could
                // send twice, which is exactly what the acceptance must not hide.
                throw ScenarioError.waitEnded(method: step.method, claimed: true)
            }
            for (name, path) in step.save ?? [:] {
                guard let value = lookup(reply, path: path) else {
                    throw ScenarioError.missingPath(method: step.method, path: path)
                }
                variables[name] = text(value)
            }
            for (path, wanted) in step.expect ?? [:] {
                let wanted = try substitute(wanted, variables)
                guard let value = lookup(reply, path: path) else {
                    throw ScenarioError.missingPath(method: step.method, path: path)
                }
                if text(value) != wanted {
                    throw ScenarioError.unexpected(
                        method: step.method, path: path, wanted: wanted, found: text(value))
                }
            }
        }
    }

    // MARK: Result

    private func saveVariables() throws {
        // Identifiers only. The passphrase and the phrase are never written.
        let data = try JSONSerialization.data(
            withJSONObject: variables, options: [.sortedKeys, .prettyPrinted])
        try data.write(to: documents.appendingPathComponent("variables.json"))
    }

    func check(_ condition: @autoclosure () throws -> Bool, _ what: String) {
        do {
            if try !condition() { fail("assertion failed: \(what)") }
        } catch {
            fail("assertion errored: \(what): \(error)")
        }
    }

    func fail(_ message: String) {
        failures.append(message)
        FileHandle.standardError.write(Data("HARNESS-FAIL \(message)\n".utf8))
    }

    private func finish(phase: String) {
        let result: [String: Any] = [
            "phase": phase,
            "ok": failures.isEmpty,
            "failures": failures,
            "notes": notes,
            "binding_api": "\(HostBindingStamp.apiMajor).\(HostBindingStamp.apiMinor)",
            "descriptor_matches": host.core.negotiated().descriptorMatches,
        ]
        if let data = try? JSONSerialization.data(
            withJSONObject: result, options: [.sortedKeys, .prettyPrinted])
        {
            try? data.write(to: documents.appendingPathComponent("result-\(phase).json"))
        }
        print("HARNESS-RESULT \(phase) ok=\(failures.isEmpty)")
    }
}

/// A one-shot flag that can be awaited with a timeout.
final class Flag: @unchecked Sendable {
    private let lock = NSLock()
    private var value = false

    func set() {
        lock.lock()
        value = true
        lock.unlock()
    }

    private func isSet() -> Bool {
        lock.lock()
        defer { lock.unlock() }
        return value
    }

    func wait(seconds: Int) async -> Bool {
        for _ in 0..<(seconds * 10) {
            if isSet() { return true }
            try? await Task.sleep(nanoseconds: 100_000_000)
        }
        return false
    }
}
