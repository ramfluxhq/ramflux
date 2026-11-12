// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

import UIKit

/// Minimal application shell for the acceptance driver. It exists only because the keychain
/// and the application lifecycle need a real app process; it shows no product UI.
final class HarnessDelegate: NSObject, UIApplicationDelegate {
    var window: UIWindow?

    func application(
        _ application: UIApplication,
        didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?
    ) -> Bool {
        let window = UIWindow(frame: UIScreen.main.bounds)
        let controller = UIViewController()
        let label = UILabel(frame: window.bounds)
        label.text = "ramflux acceptance harness"
        label.textAlignment = .center
        controller.view.backgroundColor = .systemBackground
        controller.view.addSubview(label)
        window.rootViewController = controller
        window.makeKeyAndVisible()
        self.window = window

        let arguments = ProcessInfo.processInfo.arguments
        var phase = "create-send"
        if let index = arguments.firstIndex(of: "--phase"), arguments.indices.contains(index + 1) {
            phase = arguments[index + 1]
        }
        Task.detached {
            do {
                let driver = try Driver()
                await driver.run(phase: phase)
                exit(driver.failures.isEmpty ? 0 : 1)
            } catch {
                FileHandle.standardError.write(Data("HARNESS-FAIL setup: \(error)\n".utf8))
                exit(2)
            }
        }
        return true
    }
}

@main
enum HarnessMain {
    static func main() {
        UIApplicationMain(
            CommandLine.argc, CommandLine.unsafeArgv, nil,
            NSStringFromClass(HarnessDelegate.self))
    }
}
