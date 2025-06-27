#if canImport(UIKit)
import UIKit
#endif
#if canImport(SwiftUI)
import SwiftUI
#endif
import Foundation

// MARK: - Screen Shield Manager
public final class NFSScreenShield {
    
    // MARK: - Properties
    private let configuration: NFSSecurityConfiguration.ScreenShieldConfig
    private var blurView: UIView?
    private var recordingObservation: NSKeyValueObservation?
    
    // MARK: - Initialization
    public init(configuration: NFSSecurityConfiguration.ScreenShieldConfig) {
        self.configuration = configuration
    }
    
    // MARK: - Public Methods
    
    /// Enable screen shield protection
    public func enable() {
        #if canImport(UIKit)
        guard configuration.enabled else { return }
        
        if configuration.preventScreenshots {
            enableScreenshotPrevention()
        }
        
        if configuration.preventScreenRecording {
            enableScreenRecordingPrevention()
        }
        
        if configuration.preventAirPlay {
            enableAirPlayPrevention()
        }
        
        if configuration.blurOnBackground {
            enableBackgroundBlur()
        }
        #endif
    }
    
    /// Disable screen shield protection
    @MainActor public func disable() {
        #if canImport(UIKit)
        NotificationCenter.default.removeObserver(self)
        removeBlurView()
        #endif
    }
    
    // MARK: - Private Methods
    
    #if canImport(UIKit)
    private func enableScreenshotPrevention() {
        NotificationCenter.default.addObserver(
            forName: UIApplication.userDidTakeScreenshotNotification,
            object: nil,
            queue: .main
        ) { _ in
            DispatchQueue.main.async {
                self.handleScreenshot()
            }
        }
    }
    
    private func enableScreenRecordingPrevention() {
        NotificationCenter.default.addObserver(
            forName: UIApplication.userDidTakeScreenshotNotification,
            object: nil,
            queue: .main
        ) { _ in
            DispatchQueue.main.async {
                self.handleScreenRecording()
            }
        }
    }
    
    private func enableAirPlayPrevention() {
        // AirPlay prevention is typically handled at the app level
        // This is a placeholder for future implementation
    }
    
    private func enableBackgroundBlur() {
        NotificationCenter.default.addObserver(
            forName: UIApplication.willResignActiveNotification,
            object: nil,
            queue: .main
        ) { _ in
            DispatchQueue.main.async {
                self.addBlurView()
            }
        }
        
        NotificationCenter.default.addObserver(
            forName: UIApplication.didBecomeActiveNotification,
            object: nil,
            queue: .main
        ) { _ in
            DispatchQueue.main.async {
                self.removeBlurView()
            }
        }
    }
    
    @MainActor
    private func handleScreenshot() {
        // Log screenshot attempt
        print("⚠️ Screenshot detected and prevented")
        // Show blur view as feedback
        self.addBlurView()
        DispatchQueue.main.asyncAfter(deadline: .now() + 1.0) { [weak self] in
            self?.removeBlurView()
        }
        // Additional actions can be added here
        // For example, show an alert or take other security measures
    }
    
    @MainActor private func handleScreenRecording() {
        // Log screen recording attempt
        print("⚠️ Screen recording detected and prevented")
        
        recordingObservation =  UIScreen.main.observe(\UIScreen.isCaptured, options: [.new]) { [weak self] screen, change in
            let isRecording = change.newValue ?? false
            
            if isRecording {
                DispatchQueue.main.async {
                    self?.addBlurView()
                }
            } else {
                DispatchQueue.main.async {
                    self?.removeBlurView()
                }
            }
        }
    }
    
    @MainActor private func addBlurView() {
        guard let window = UIApplication.shared.windows.first else { return }
        
        let blurEffect = UIBlurEffect(style: configuration.customBlurStyle)
        let blurView = UIVisualEffectView(effect: blurEffect)
        blurView.frame = window.bounds
        blurView.tag = 999 // Tag for removal
        blurView.alpha = 0
        
        window.addSubview(blurView)
        
        UIView.animate(withDuration: 0.3) {
            blurView.alpha = 1.0
        }
        
        self.blurView = blurView
    }
    
    @MainActor private func removeBlurView() {
        guard let blurView = blurView else { return }
        
        UIView.animate(withDuration: 0.3, animations: {
            blurView.alpha = 0
        }) { _ in
            blurView.removeFromSuperview()
            self.blurView = nil
        }
    }
    #endif
}

// MARK: - SwiftUI Support
#if canImport(SwiftUI)
@available(iOS 13.0, *)
public struct SecureView<Content: View>: View {
    private let content: Content
    private let configuration: NFSSecurityConfiguration.ScreenShieldConfig
    
    public init(configuration: NFSSecurityConfiguration.ScreenShieldConfig, @ViewBuilder content: () -> Content) {
        self.configuration = configuration
        self.content = content()
    }
    
    public var body: some View {
        content
            .onAppear {
                let screenShield = NFSScreenShield(configuration: configuration)
                screenShield.enable()
            }
            .onDisappear {
                let screenShield = NFSScreenShield(configuration: configuration)
                screenShield.disable()
            }
    }
}

@available(iOS 13.0, *)
public struct BlurredBackgroundView: View {
    private let style: UIBlurEffect.Style
    
    public init(style: UIBlurEffect.Style = .systemMaterial) {
        self.style = style
    }
    
    public var body: some View {
        ZStack {
            if #available(iOS 14.0, *) {
                Color.clear
                    .background(
                        BlurView(style: style)
                            .ignoresSafeArea()
                    )
            } else {
                BlurView(style: style)
            }
        }
    }
}

@available(iOS 13.0, *)
private struct BlurView: UIViewRepresentable {
    let style: UIBlurEffect.Style
    
    func makeUIView(context: Context) -> UIVisualEffectView {
        let blurEffect = UIBlurEffect(style: style)
        return UIVisualEffectView(effect: blurEffect)
    }
    
    func updateUIView(_ uiView: UIVisualEffectView, context: Context) {
        // No updates needed
    }
}
#endif

extension UIView {
    
    private struct Constants {
        static var secureTextFieldTag: Int { 54321 }
    }
    
    func setScreenCaptureProtection(secureTextFieldTag:Int = 0) {
        if viewWithTag(Constants.secureTextFieldTag) is UITextField {
            return
        }
        
        guard superview != nil else {
            for subview in subviews {
                subview.setScreenCaptureProtection()
            }
            return
        }
        
        let secureTextField = UITextField()
        secureTextField.backgroundColor = .clear
        secureTextField.translatesAutoresizingMaskIntoConstraints = false
        secureTextField.tag = Constants.secureTextFieldTag
        secureTextField.isSecureTextEntry = true
        
        insertSubview(secureTextField, at: 0)
        secureTextField.isUserInteractionEnabled = false
        
#if os(iOS)
        layer.superlayer?.addSublayer(secureTextField.layer)
        secureTextField.layer.sublayers?.last?.addSublayer(layer)
        
        secureTextField.topAnchor.constraint(equalTo: self.topAnchor, constant: 0).isActive = true
        secureTextField.bottomAnchor.constraint(equalTo: self.bottomAnchor, constant: 0).isActive = true
        secureTextField.leadingAnchor.constraint(equalTo: self.leadingAnchor, constant: 0).isActive = true
        secureTextField.trailingAnchor.constraint(equalTo: self.trailingAnchor, constant: 0).isActive = true
#else
        secureTextField.frame = bounds
        secureTextField.wantsLayer = true
        secureTextField.layer?.addSublayer(layer!)
        addSubview(secureTextField)
#endif
    }
}

public struct ProtectScreenshot: ViewModifier {
    public func body(content: Content) -> some View {
        ScreenshotProtectView { content }
    }
}

public extension View {
    func protectScreenshot() -> some View {
        modifier(ProtectScreenshot())
    }
}

struct ScreenshotProtectView<Content: View>: UIViewControllerRepresentable {
    typealias UIViewControllerType = ScreenshotProtectingHostingViewController<Content>
    
    private let content: () -> Content
    
    init(@ViewBuilder content: @escaping () -> Content) {
        self.content = content
    }
    
    func makeUIViewController(context: Context) -> UIViewControllerType {
        ScreenshotProtectingHostingViewController(content: content)
    }
    
    func updateUIViewController(_ uiViewController: UIViewControllerType, context: Context) {}
}

final class ScreenshotProtectingHostingViewController<Content: View>: UIViewController {
    private let content: () -> Content
    private let wrapperView = ScreenshotProtectingView()
    
    init(@ViewBuilder content: @escaping () -> Content) {
        self.content = content
        super.init(nibName: nil, bundle: nil)
        setupUI()
    }
    
    required init?(coder: NSCoder) {
        fatalError("❌ init(coder:) has not been implemented")
    }
    
    private func setupUI() {
        view.addSubview(wrapperView)
        wrapperView.translatesAutoresizingMaskIntoConstraints = false
        NSLayoutConstraint.activate([
            wrapperView.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            wrapperView.trailingAnchor.constraint(equalTo: view.trailingAnchor),
            wrapperView.topAnchor.constraint(equalTo: view.topAnchor),
            wrapperView.bottomAnchor.constraint(equalTo: view.bottomAnchor)
        ])
        
        let hostVC = UIHostingController(rootView: content())
        hostVC.view.translatesAutoresizingMaskIntoConstraints = false
        
        addChild(hostVC)
        wrapperView.setup(contentView: hostVC.view)
        hostVC.didMove(toParent: self)
    }
}

public final class ScreenshotProtectingView: UIView {
    
    private var contentView: UIView?
    private let textField = UITextField()
    private lazy var secureContainer: UIView? = try? getSecureContainer(from: textField)
    
    init(contentView: UIView? = nil) {
        self.contentView = contentView
        super.init(frame: .zero)
        setupUI()
    }
    
    required init?(coder aDecoder: NSCoder) {
        fatalError("❌ init(coder:) has not been implemented")
    }
    
    private func setupUI() {
        textField.backgroundColor = .clear
        textField.isUserInteractionEnabled = false
        textField.isSecureTextEntry = true
        
        guard let container = secureContainer else { return }
        
        addSubview(container)
        container.translatesAutoresizingMaskIntoConstraints = false
        
        NSLayoutConstraint.activate([
            container.leadingAnchor.constraint(equalTo: leadingAnchor),
            container.trailingAnchor.constraint(equalTo: trailingAnchor),
            container.topAnchor.constraint(equalTo: topAnchor),
            container.bottomAnchor.constraint(equalTo: bottomAnchor)
        ])
        
        guard let contentView = contentView else { return }
        setup(contentView: contentView)
    }
    
    func setup(contentView: UIView) {
        self.contentView?.removeFromSuperview()
        self.contentView = contentView
        
        guard let container = secureContainer else { return }
        
        container.addSubview(contentView)
        container.isUserInteractionEnabled = isUserInteractionEnabled
        contentView.translatesAutoresizingMaskIntoConstraints = false
        
        let bottomConstraint = contentView.bottomAnchor.constraint(equalTo: container.bottomAnchor)
        bottomConstraint.priority = .required - 1
        
        NSLayoutConstraint.activate([
            contentView.leadingAnchor.constraint(equalTo: container.leadingAnchor),
            contentView.trailingAnchor.constraint(equalTo: container.trailingAnchor),
            contentView.topAnchor.constraint(equalTo: container.topAnchor),
            bottomConstraint
        ])
    }
    
    func getSecureContainer(from view: UIView) throws -> UIView {
        let containerName: String
        
        if #available(iOS 15, *) {
            containerName = "_UITextLayoutCanvasView"
        } else {
            let currentIOSVersion = (UIDevice.current.systemVersion as NSString).floatValue
            throw NSError(domain: "YourDomain", code: -1, userInfo: ["UnsupportedVersion": currentIOSVersion])
        }
        
        let containers = view.subviews.filter { type(of: $0).description() == containerName }
        
        guard let container = containers.first else {
            throw NSError(domain: "YourDomain", code: -1, userInfo: ["ContainerNotFound": containerName])
        }
        
        return container
    }
}
