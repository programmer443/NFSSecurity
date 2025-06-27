//
//  SecurityExampleApp.swift
//  SecurityExample
//
//  Created by Muhammad Ahmad Munir on 27/06/2025.
//

import SwiftUI
import NFSSecurity

@main
struct SecurityExampleApp: App {
    let screenShield: NFSScreenShield

    init() {
        // Custom screen shield configuration
        let screenShieldConfig = NFSSecurityConfiguration.ScreenShieldConfig(
            enabled: true,
            preventScreenshots: true,
            preventScreenRecording: true,
            preventAirPlay: true,
            blurOnBackground: true,
            customBlurStyle: .systemUltraThinMaterialDark
        )
        self.screenShield = NFSScreenShield(configuration: screenShieldConfig)
        self.screenShield.enable()
    }
    var body: some Scene {
        WindowGroup {
            if #available(iOS 13.0, *) {
                SecureView(configuration: NFSSecurityConfiguration.ScreenShieldConfig()) {
                    ContentView()
                }
            } else {
                ContentView()
            }
        }
    }
}
