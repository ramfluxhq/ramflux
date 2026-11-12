// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

import Foundation
import Network

#if canImport(UIKit)
import UIKit
#endif

/// Owns the one core of the process and connects it to the platform: the data root in the
/// app's own container, the path monitor, and the background task around suspension.
///
/// The host never opens a second core for the same data root, and no extension may use this
/// type: in v1 only the app process opens the store.
public final class RamfluxHost: @unchecked Sendable {
    public let core: RamfluxCore
    public let dataRoot: URL

    private let lifecycleQueue = DispatchQueue(label: "ramflux.host.lifecycle")
    private let pathQueue = DispatchQueue(label: "ramflux.host.path")
    private var monitor: NWPathMonitor?
    private var hadPath = false
    private var lastLabel = Data()
    private var observers: [NSObjectProtocol] = []

    /// The data root: `Library/Application Support/ramflux` inside the app's own container.
    /// Never an App Group container. Backup exclusion and the data-protection class are set
    /// on the directory by the core when it starts.
    public static func defaultDataRoot() throws -> URL {
        let support = try FileManager.default.url(
            for: .applicationSupportDirectory, in: .userDomainMask,
            appropriateFor: nil, create: true)
        let root = support.appendingPathComponent("ramflux", isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        return root
    }

    /// Create the core. Throws `CoreError.UnsupportedVersion` when the generated bindings
    /// and the linked library are not compatible.
    public init(dataRoot: URL? = nil, maxPendingUpdates: UInt32 = 512) throws {
        let root = try dataRoot ?? RamfluxHost.defaultDataRoot()
        self.dataRoot = root
        let handshake = HostHandshake(
            api: ApiVersion(
                major: HostBindingStamp.apiMajor, minor: HostBindingStamp.apiMinor),
            descriptorFingerprint: HostBindingStamp.descriptorFingerprint,
            capabilities: ["execute.v1", "lifecycle.v1", "network.v1", "subscribe.credit.v1"])
        self.core = try RamfluxCore.open(
            config: CoreConfig(
                dataRoot: root.path,
                handshake: handshake,
                maxPendingUpdates: maxPendingUpdates))
    }

    deinit {
        monitor?.cancel()
        for observer in observers {
            NotificationCenter.default.removeObserver(observer)
        }
    }

    // MARK: Lifecycle

    /// Start the core (blocking work runs off the caller's thread) and the path monitor.
    public func start() async throws {
        try await onLifecycleQueue { try self.core.start() }
        startPathMonitor()
    }

    /// Close every store and release every file lock. Returns the evidence the core
    /// observed; `dataRootLockReleased` must be true before the process may be suspended.
    @discardableResult
    public func suspend() async throws -> SuspendEvidence {
        try await onLifecycleQueue { try self.core.suspend() }
    }

    public func resume() async throws {
        try await onLifecycleQueue { try self.core.resume() }
    }

    public func close() async throws {
        monitor?.cancel()
        monitor = nil
        try await onLifecycleQueue { try self.core.close() }
    }

    private func onLifecycleQueue<T>(
        _ work: @escaping @Sendable () throws -> T
    ) async throws -> T {
        try await withCheckedThrowingContinuation { continuation in
            lifecycleQueue.async {
                continuation.resume(with: Result { try work() })
            }
        }
    }

    #if canImport(UIKit)
    /// Follow the application lifecycle. On entering the background the host starts a
    /// background task, suspends the core, and ends the task only after the core reported
    /// the released lock. On returning to the foreground it resumes the core.
    @MainActor
    public func followApplicationLifecycle(
        onError: @escaping @Sendable (Error) -> Void = { _ in }
    ) {
        let center = NotificationCenter.default
        let background = center.addObserver(
            forName: UIApplication.didEnterBackgroundNotification, object: nil, queue: .main
        ) { [weak self] _ in
            // Delivered on the main queue. The background task must begin before this
            // handler returns, so it is started synchronously here.
            MainActor.assumeIsolated {
                guard let self else { return }
                let task = BackgroundTask()
                task.begin(name: "ramflux.suspend")
                Task { @MainActor in
                    do {
                        let evidence = try await self.suspend()
                        if !evidence.dataRootLockReleased {
                            onError(RamfluxHostError.lockStillHeldAtSuspension)
                        }
                    } catch {
                        onError(error)
                    }
                    // Ended only after the core reported the released lock (or failed).
                    task.end()
                }
            }
        }
        let foreground = center.addObserver(
            forName: UIApplication.willEnterForegroundNotification, object: nil, queue: .main
        ) { [weak self] _ in
            guard let self else { return }
            Task {
                do {
                    if self.core.state() == .suspended {
                        try await self.resume()
                    }
                } catch {
                    onError(error)
                }
            }
        }
        observers.append(contentsOf: [background, foreground])
    }
    #endif

    // MARK: Network path

    /// Report default-network changes to the core. Leaving the foreground is not a network
    /// change; that is `suspend()`.
    private func startPathMonitor() {
        guard monitor == nil else { return }
        let monitor = NWPathMonitor()
        monitor.pathUpdateHandler = { [weak self] path in
            self?.report(path)
        }
        monitor.start(queue: pathQueue)
        self.monitor = monitor
    }

    private func report(_ path: NWPath) {
        guard path.status == .satisfied else {
            if hadPath {
                hadPath = false
                lastLabel = Data()
                core.networkChanged(change: .lost)
            }
            return
        }
        // An opaque label per network: interface type and name. The core hashes it and
        // never stores or logs the label itself.
        let interface = path.availableInterfaces.first
        let kind: String
        switch interface?.type {
        case .wifi: kind = "wifi"
        case .cellular: kind = "cellular"
        case .wiredEthernet: kind = "wired"
        case .loopback: kind = "loopback"
        default: kind = "other"
        }
        let label = Data("\(kind)/\(interface?.name ?? "")".utf8)
        if !hadPath {
            hadPath = true
            lastLabel = label
            core.networkChanged(change: .available(label: label))
        } else {
            // Any later update while satisfied may be a new address or NAT64 prefix on the
            // same interface, so it is reported as a change even when the label is equal.
            lastLabel = label
            core.networkChanged(change: .changed(label: label))
        }
    }
}

#if canImport(UIKit)
/// One UIKit background task. Used on the main actor only.
@MainActor
private final class BackgroundTask {
    private var identifier = UIBackgroundTaskIdentifier.invalid

    func begin(name: String) {
        identifier = UIApplication.shared.beginBackgroundTask(withName: name) { [weak self] in
            // Expiration: the system suspends the process regardless. The core's own
            // suspend deadline bounds the work that is still running.
            MainActor.assumeIsolated { self?.end() }
        }
    }

    func end() {
        guard identifier != .invalid else { return }
        UIApplication.shared.endBackgroundTask(identifier)
        identifier = .invalid
    }
}
#endif

public enum RamfluxHostError: Error, Sendable {
    /// The core returned from `suspend` without observing the released data-root lock.
    case lockStillHeldAtSuspension
}
