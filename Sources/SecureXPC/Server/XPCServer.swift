//
//  XPCServer.swift
//  SecureXPC
//
//  Created by Josh Kaplan on 2021-10-09
//

import Foundation

/// An XPC server to receive requests from and send responses to an ``XPCClient``.
///
/// ### Retrieving a Server
/// There are two different types of services you can retrieve a server for: XPC services and XPC Mach services. If you're uncertain which type of service you're
/// using, it's likely an XPC service.
///
/// Anonymous servers can also be created which do not correspond to an XPC service or XPC Mach service.
///
/// #### XPC services
/// These are helper tools which ship as part of your app and only your app can communicate with.
///
/// To retrieve a server for an XPC service:
/// ```swift
/// let server = try XPCServer.forThisXPCService()
/// ```
///
/// #### XPC Mach services
/// Launch Agents, Launch Daemons, helper tools installed with
/// [`SMJobBless`](https://developer.apple.com/documentation/servicemanagement/1431078-smjobbless), and login items installed with
/// [`SMLoginItemSetEnabled`](https://developer.apple.com/documentation/servicemanagement/1501557-smloginitemsetenabled) can
/// optionally communicate over XPC by using Mach services.
///
/// In most cases, a server can be auto-configured using ``XPCServer/forThisBlessedHelperTool()`` for a helper tool installed with `SMJobBless`:
/// ```swift
/// let server = try XPCServer.forThisBlessedHelperTool()
/// ```
///
/// Similarly, a server can be auto-configured using ``XPCServer/forThisLoginItem()`` for a login item installed with `SMLoginItemSetEnabled`.
///
/// For Launch Agents, Launch Daemons, more advanced `SMJobBless` and `SMLoginItemSetEnabled` configurations, as well as other cases it is
/// necessary both to the specify the name of the service as well its security requirements. See
/// ``XPCServer/forThisMachService(named:clientRequirements:)`` for an example and details.
///
/// #### Anonymous servers
/// An anonymous server can be created by any macOS program. Use cases for making one include:
///  - Allowing two processes which are not XPC services to communicate over XPC with each other. This is done by having one of those processes make an
///    anonymous server and send its ``XPCNonBlockingServer/endpoint`` to an XPC Mach service. The other process then needs to retrieve that
///    endpoint from the XPC Mach service and create a client using ``XPCClient/forEndpoint(_:)``.
///  - Testing code that would otherwise run as part of an XPC Mach service without needing to install a helper tool. However, note that this code won't run as root.
///
/// ### Registering & Handling Routes
/// Once a server instance has been retrieved, one or more routes should be registered with it. This is done by calling one of the `registerRoute` functions and
/// providing a route and a compatible closure or function. For example:
/// ```swift
///     ...
///     let updateRoute = XPCRoute.named("config", "update")
///                               .withMessageType(Config.self)
///                               .withReplyType(Config.self)
///     server.registerRoute(updateRoute, handler: updateConfig)
/// }
///
/// private func updateConfig(_ config: Config) throws -> Config {
///     <# implementation here #>
/// }
/// ```
///
/// Routes with sequential reply types can respond to the client arbitrarily many times and therefore must explicitly provide responses to a
/// ``SequentialResultProvider``:
/// ```swift
///     ...
///     let changesRoute = XPCRoute.named("config", "changes")
///                                .withSequentialReplyType(Config.self)
///     server.registerRoute(changesRoute, handler: configChanges)
/// }
///
/// private func configChanges(provider: SequentialResultProvider<Config>) {
///     <# implementation here #>
/// }
/// ```
///
/// On macOS 10.15 and later async functions and closures can also be registered as the handler for a route. For command line tools, such as the helper tools
/// installed with `SMJobBless`, async functions and closures are only supported on macOS 12 and later. This is an
/// [Apple limitation](https://developer.apple.com/forums/thread/701969) unrelated to SecureXPC.
///
/// ### Starting a Server
/// Once all of the routes are registered, the server must be told to start processing requests. In most cases this should be done with:
/// ```swift
/// server.startAndBlock()
/// ```
///
/// Returned server instances which conform to ``XPCNonBlockingServer`` can also be started in a non-blocking manner:
/// ```swift
/// server.start()
/// ```
///
/// ## Topics
/// ### Retrieving a Server
/// - ``forThisXPCService()`` 
/// - ``forThisBlessedHelperTool()``
/// - ``forThisLoginItem()``
/// - ``forThisMachService(named:clientRequirements:)``
/// - ``makeAnonymous()``
/// - ``makeAnonymous(clientRequirements:)``
/// ### Registering Async Routes
/// - ``registerRoute(_:handler:)-6htah``
/// - ``registerRoute(_:handler:)-g7ww``
/// - ``registerRoute(_:handler:)-rw2w``
/// - ``registerRoute(_:handler:)-2vk6u``
/// - ``registerRoute(_:handler:)-7r1hv``
/// - ``registerRoute(_:handler:)-7ngxn``
/// ### Registering Synchronous Routes
/// - ``registerRoute(_:handler:)-4ttqe``
/// - ``registerRoute(_:handler:)-9a0x9``
/// - ``registerRoute(_:handler:)-4fxv0``
/// - ``registerRoute(_:handler:)-1jw9d``
/// - ``registerRoute(_:handler:)-6sxby``
/// - ``registerRoute(_:handler:)-qcox``
/// ### Configuring a Server
/// - ``handlerConcurrency-swift.property``
/// - ``HandlerConcurrency-swift.enum``
/// - ``setErrorHandler(_:)-lex4``
/// - ``setErrorHandler(_:)-1r3up``
/// ### Starting a Server
/// - ``startAndBlock()``
/// - ``XPCNonBlockingServer/start()``
/// ### Server State
/// - ``serviceName``
/// - ``XPCNonBlockingServer/endpoint``
public class XPCServer {
    
    /// The concurrency model used when running registered handlers.
    public enum HandlerConcurrency {
        /// Requests will be routed to handlers concurrently without regard to the originating client.
        case concurrent
        /// Requests will be routed such that only one handler is running simultaneously per originating client.
        ///
        /// Handlers may be called concurrently when requests originate from different clients.
        ///
        /// Requests will be procesed in the order in which they are received by the server; however, this is not guaranteed to match the order in which `send`
        /// or `sendMessage` calls are made by an ``XPCClient`` due to their asynchronous nature. If a client requires a server to receive requests in a
        /// specific order, it must wait until a `send` or `sendMessage` call has completed before calling the next one.
        case serialPerClient
        /// Requests will be routed such that only one handler is running simultaneously per server.
        ///
        /// Handlers may be called concurrently if they are registered with multiple servers.
        ///
        /// Requests will be procesed in the order in which they are received by the server; however, this is not guaranteed to match the order in which `send` or
        /// `sendMessage` calls are made by an ``XPCClient`` due to their asynchronous nature nor is there any guaranteed ordering from calls made by
        /// multiple clients. If a client requires a server to receive requests in a specific order, it must wait until a `send` or `sendMessage` call has completed
        /// before calling the next one.
        case serialPerServer
    }
    
    /// Governs how incoming requests are scheduled with registered handlers.
    ///
    /// By default handlers are scheduled with ``HandlerConcurrency-swift.enum/concurrent``. Scheduling applies to both synchronous and
    /// `async` handlers.
    ///
    /// This property is thread-safe and can be updated at any time both before and after the server has been started. However, after the server has been started
    /// when setting a new value the scheduling behavior is undefined for received requests which have not yet had their handler run to completion.
    public var handlerConcurrency: HandlerConcurrency {
        get {
            self.requestQueue.getHandlerConcurrency()
        }
        set(concurrency) {
            self.requestQueue.setHandlerConcurrency(concurrency)
        }
    }
    
    /// Stores and schedules all incoming requests and their associated handler.
    private let requestQueue = RequestQueue(handlerConcurrency: .concurrent)
    
    /// Used to determine whether an incoming XPC message from a client should be processed and handed off to a registered route.
    internal let messageAcceptor: MessageAcceptor
    
    internal init(messageAcceptor: MessageAcceptor) {
        self.messageAcceptor = messageAcceptor
    }
    
    // MARK: Route registration
    
    private var routes = [XPCRoute : XPCHandler]()
        
    /// Internal function that actually registers the route and enforces that a route is only ever registered once.
    ///
    /// All of the public functions exist to satisfy type constraints.
    private func registerRoute(_ route: XPCRoute, handler: XPCHandler) {
        if let _ = self.routes.updateValue(handler, forKey: route) {
            fatalError("Route \(route.pathComponents) is already registered")
        }
    }
        
    /// Registers a route for a request without a message that does not receive a reply.
    ///
    /// > Important: Routes can only be registered with a handler once; it is a programming error to provide a route which has already been registered.
    ///
    /// - Parameters:
    ///   - route: A route that has no message and can't receive a reply.
    ///   - handler: Will be called when the server receives an incoming request for this route if the request is accepted.
    public func registerRoute(_ route: XPCRouteWithoutMessageWithoutReply,
                              handler: @escaping () throws -> Void) {
        self.registerRoute(route.route, handler: ConstrainedXPCHandlerWithoutMessageWithoutReplySync(handler: handler))
    }
    
    /// Registers a route for a request without a message that does not receive a reply.
    ///
    /// > Important: Routes can only be registered with a handler once; it is a programming error to provide a route which has already been registered.
    ///
    /// - Parameters:
    ///   - route: A route that has no message and can't receive a reply.
    ///   - handler: Will be called when the server receives an incoming request for this route if the request is accepted.
    @available(macOS 10.15.0, *)
    public func registerRoute(_ route: XPCRouteWithoutMessageWithoutReply,
                              handler: @escaping () async throws -> Void) {
        self.registerRoute(route.route, handler: ConstrainedXPCHandlerWithoutMessageWithoutReplyAsync(handler: handler))
    }
    
    /// Registers a route for a request with a message that does not receive a reply.
    ///
    /// > Important: Routes can only be registered with a handler once; it is a programming error to provide a route which has already been registered.
    ///
    /// - Parameters:
    ///   - route: A route that has a message and can't receive a reply.
    ///   - handler: Will be called when the server receives an incoming request for this route if the request is accepted.
    public func registerRoute<M: Decodable>(_ route: XPCRouteWithMessageWithoutReply<M>,
                                            handler: @escaping (M) throws -> Void) {
        self.registerRoute(route.route, handler: ConstrainedXPCHandlerWithMessageWithoutReplySync(handler: handler))
    }
    
    /// Registers a route for a request with a message that does not receive a reply.
    ///
    /// > Important: Routes can only be registered with a handler once; it is a programming error to provide a route which has already been registered.
    ///
    /// - Parameters:
    ///   - route: A route that has a message and can't receive a reply.
    ///   - handler: Will be called when the server receives an incoming request for this route if the request is accepted.
    @available(macOS 10.15.0, *)
    public func registerRoute<M: Decodable>(_ route: XPCRouteWithMessageWithoutReply<M>,
                                            handler: @escaping (M) async throws -> Void) {
        self.registerRoute(route.route, handler: ConstrainedXPCHandlerWithMessageWithoutReplyAsync(handler: handler))
    }
    
    /// Registers a route for a request without a message that receives a reply.
    ///
    /// > Important: Routes can only be registered with a handler once; it is a programming error to provide a route which has already been registered.
    ///
    /// - Parameters:
    ///   - route: A route that has no message and expects a reply.
    ///   - handler: Will be called when the server receives an incoming request for this route if the request is accepted.
    public func registerRoute<R: Decodable>(_ route: XPCRouteWithoutMessageWithReply<R>,
                                            handler: @escaping () throws -> R) {
        self.registerRoute(route.route, handler: ConstrainedXPCHandlerWithoutMessageWithReplySync(handler: handler))
    }
    
    /// Registers a route for a request without a message that receives a reply.
    ///
    /// > Important: Routes can only be registered with a handler once; it is a programming error to provide a route which has already been registered.
    ///
    /// - Parameters:
    ///   - route: A route that has no message and expects a reply.
    ///   - handler: Will be called when the server receives an incoming request for this route if the request is accepted.
    @available(macOS 10.15.0, *)
    public func registerRoute<R: Decodable>(_ route: XPCRouteWithoutMessageWithReply<R>,
                                            handler: @escaping () async throws -> R) {
        self.registerRoute(route.route, handler: ConstrainedXPCHandlerWithoutMessageWithReplyAsync(handler: handler))
    }
    
    /// Registers a route for a request with a message that receives a reply.
    ///
    /// > Important: Routes can only be registered with a handler once; it is a programming error to provide a route which has already been registered.
    ///
    /// - Parameters:
    ///   - route: A route that has a message and expects a reply.
    ///   - handler: Will be called when the server receives an incoming request for this route if the request is accepted.
    public func registerRoute<M: Decodable, R: Encodable>(_ route: XPCRouteWithMessageWithReply<M, R>,
                                                          handler: @escaping (M) throws -> R) {
        self.registerRoute(route.route, handler: ConstrainedXPCHandlerWithMessageWithReplySync(handler: handler))
    }
    
    /// Registers a route for a request with a message that receives a reply.
    ///
    /// > Important: Routes can only be registered with a handler once; it is a programming error to provide a route which has already been registered.
    ///
    /// - Parameters:
    ///   - route: A route that has a message and expects a reply.
    ///   - handler: Will be called when the server receives an incoming request for this route if the request is accepted.
    @available(macOS 10.15.0, *)
    public func registerRoute<M: Decodable, R: Encodable>(_ route: XPCRouteWithMessageWithReply<M, R>,
                                                          handler: @escaping (M) async throws -> R) {
        self.registerRoute(route.route, handler: ConstrainedXPCHandlerWithMessageWithReplyAsync(handler: handler))
    }
    
    /// Registers a route for a request without a message that can receive sequential responses.
    ///
    /// > Important: Routes can only be registered with a handler once; it is a programming error to provide a route which has already been registered.
    ///
    /// - Parameters:
    ///   - route: A route that has no message and can receive zero or more sequential replies.
    ///   - handler: Will be called when the server receives an incoming request for this route if the request is accepted.
    public func registerRoute<S: Encodable>(
        _ route: XPCRouteWithoutMessageWithSequentialReply<S>,
        handler: @escaping (SequentialResultProvider<S>) -> Void
    ) {
        let constrainedHandler = ConstrainedXPCHandlerWithoutMessageWithSequentialReplySync(handler: handler)
        self.registerRoute(route.route, handler: constrainedHandler)
    }
    
    /// Registers a route for a request without a message that can receive sequential replies.
    ///
    /// > Important: Routes can only be registered with a handler once; it is a programming error to provide a route which has already been registered.
    ///
    /// - Parameters:
    ///   - route: A route that has no message and can receive zero or more sequential replies.
    ///   - handler: Will be called when the server receives an incoming request for this route if the request is accepted.
    @available(macOS 10.15.0, *)
    public func registerRoute<S: Encodable>(
        _ route: XPCRouteWithoutMessageWithSequentialReply<S>,
        handler: @escaping (SequentialResultProvider<S>) async -> Void
    ) {
        let constrainedHandler = ConstrainedXPCHandlerWithoutMessageWithSequentialReplyAsync(handler: handler)
        self.registerRoute(route.route, handler: constrainedHandler)
    }
    
    /// Registers a route for a request with a message that can receive sequential replies.
    ///
    /// > Important: Routes can only be registered with a handler once; it is a programming error to provide a route which has already been registered.
    ///
    /// - Parameters:
    ///   - route: A route that has a message and can receive zero or more sequential responses.
    ///   - handler: Will be called when the server receives an incoming request for this route if the request is accepted.
    public func registerRoute<M: Decodable, S: Encodable>(
        _ route: XPCRouteWithMessageWithSequentialReply<M, S>,
        handler: @escaping (M, SequentialResultProvider<S>) -> Void
    ) {
        let constrainedHandler = ConstrainedXPCHandlerWithMessageWithSequentialReplySync(handler: handler)
        self.registerRoute(route.route, handler: constrainedHandler)
    }
    
    /// Registers a route for a request with a message that can receive sequential replies.
    ///
    /// > Important: Routes can only be registered with a handler once; it is a programming error to provide a route which has already been registered.
    ///
    /// - Parameters:
    ///   - route: A route that has a message and can receive zero or more sequential responses.
    ///   - handler: Will be called when the server receives an incoming request for this route if the request is accepted.
    @available(macOS 10.15.0, *)
    public func registerRoute<M: Decodable, S: Encodable>(
        _ route: XPCRouteWithMessageWithSequentialReply<M, S>,
        handler: @escaping (M, SequentialResultProvider<S>) async -> Void
    ) {
        let constrainedHandler = ConstrainedXPCHandlerWithMessageWithSequentialReplyAsync(handler: handler)
        self.registerRoute(route.route, handler: constrainedHandler)
    }
    
    internal func startClientConnection(_ connection: xpc_connection_t) {
        // Listen for events (messages or errors) coming from this connection
        xpc_connection_set_event_handler(connection, { event in
            self.handleEvent(connection: connection, event: event)
        })

        // Start the connection
        xpc_connection_resume(connection)
    }
    
    private func handleEvent(connection: xpc_connection_t, event: xpc_object_t) {
        // Only dictionary types and errors are expected. If it's not a dictionary and not an XPC C API error, then that
        // itself is an error and `XPCError.fromXPCObject` will properly handle this case.
        // Note that we're intentionally not checking for message acceptance as errors generated by libxpc can fail to
        // meet the acceptor's criteria because they're not coming from the client.
        guard xpc_get_type(event) == XPC_TYPE_DICTIONARY else {
            self.serverErrorHandler.handle(XPCError.fromXPCObject(event))
            return
        }
        
        guard self.messageAcceptor.acceptMessage(connection: connection, message: event) else {
            self.serverErrorHandler.handle(.insecure)
            return
        }
        self.handleMessage(connection: connection, message: event)
    }
    
    private func handleMessage(connection: xpc_connection_t, message: xpc_object_t) {
        let request: Request
        do {
            request = try Request(dictionary: message)
        } catch {
            var reply = xpc_dictionary_create_reply(message)
            self.handleError(error, request: nil, connection: connection, reply: &reply)
            return
        }
        
        guard let handler = self.routes[request.route] else {
            let error = XPCError.routeNotRegistered(request.route.pathComponents)
            var reply = xpc_dictionary_create_reply(message)
            self.handleError(error, request: request, connection: connection, reply: &reply)
            return
        }
        
        self.requestQueue.enqueue(request: request, handler: handler, connection: connection) { [weak self] in
            // Wrap the error handler function such that it doesn't retain this server instance
            self?.handleError($0, request: $1, connection: $2, reply: &$3)
        }
    }
    
    // MARK: Error handling
    
    private var serverErrorHandler = ServerErrorHandler.none
    
    /// Sets a handler to synchronously receive any errors encountered.
    ///
    /// This will replace any previously set error handler, including an asynchronous one.
    public func setErrorHandler(_ handler: @escaping (XPCError) -> Void) {
        self.serverErrorHandler = .sync(handler)
    }
    
    /// Sets a handler to asynchronously receive any errors encountered.
    ///
    /// This will replace any previously set error handler, including a synchronous one.
    @available(macOS 10.15.0, *)
    public func setErrorHandler(_ handler: @escaping (XPCError) async -> Void) {
        self.serverErrorHandler = .async(handler)
    }
    
    private func handleError(
        _ error: Error,
        request: Request?,
        connection: xpc_connection_t?,
        reply: inout xpc_object_t?
    ) {
        let error = XPCError.asXPCError(error: error)
        self.serverErrorHandler.handle(error)
        
        // If it's possible to reply, then send the error back to the client
        if var nonNilReply = reply, let connection = connection {
            do {
                try Response.encodeError(error, intoReply: &nonNilReply)
                try maybeSendReply(&reply, request: request, connection: connection)
            } catch {
                // If these actions fail, then there's no way to proceed
            }
        }
    }

	// MARK: Abstract methods & properties
    
    /// Begins processing requests received by this XPC server and never returns.
    ///
    /// If this server is for an XPC service, how the server will run is determined by the info property list's
    /// [`RunLoopType`](https://developer.apple.com/documentation/bundleresources/information_property_list/xpcservice/runlooptype?changes=l_3).
    /// If no value is specified, `dispatch_main` is the default. If `dispatch_main` is specified or defaulted to, it is a programming error to call this function
    /// from any thread besides the main thread.
    ///
    /// If this server is for a Mach service or is an anonymous server, it is always a programming error to call this function from any thread besides the main thread.
    public func startAndBlock() -> Never {
        fatalError("Abstract Method")
    }
    
    /// The name of the service this server is bound to.
    ///
    /// Anonymous servers do not represent a service and therefore will always have a `nil` service name.
    public var serviceName: String? {
        fatalError("Abstract Property")
    }
}

// MARK: public server protocols

/// An ``XPCServer`` which can be started in a non-blocking manner.
///
/// > Warning: Do not implement this protocol. Additions made to this protocol will not be considered a breaking change for SemVer purposes.
public protocol XPCNonBlockingServer {
    /// Begins processing requests received by this XPC server.
    func start()
    
    /// Retrieve an endpoint for this XPC server and then use ``XPCClient/forEndpoint(_:)`` to create a client.
    ///
    /// Endpoints can be sent across an XPC connection.
    var endpoint: XPCServerEndpoint { get }
    
    // Internal implementation note: `endpoint` is part of the `XPCNonBlockingServer` protocol instead of `XPCServer` as
    // `XPCServiceServer` can't have an endpoint created for it.
    
    // From a technical perspective this is because endpoints are only created from connection listeners, which an XPC
    // service doesn't expose (incoming connections are simply passed to the handler provided to `xpc_main(...)`. From a
    // security point of view, it makes sense that it's not possible to create an endpoint for an XPC service because
    // they're designed to only allow communication between the main app and .xpc bundles contained within the same main
    // app's bundle. As such there's no valid use case for creating such an endpoint.
}

// MARK: public factories

// Contains all of the `static` code that provides the entry points to retrieving an `XPCServer` instance.
extension XPCServer {
    /// Provides a server for this XPC service.
    ///
    /// > Important: No requests will be processed until ``startAndBlock()`` is called.
    ///
    /// - Throws: ``XPCError/notXPCService`` if the caller is not an XPC service.
    /// - Returns: A server instance configured for this XPC service.
    public static func forThisXPCService() throws -> XPCServer {
        try XPCServiceServer._forThisXPCService()
    }
    
    /// Creates a new anonymous server that accepts requests from the same process it's running in.
    ///
    /// Only a client created from an anonymous server's endpoint can communicate with that server. Do this by retrieving the server's
    /// ``XPCNonBlockingServer/endpoint`` and then creating a client with it:
    /// ```swift
    /// let server = XPCServer.makeAnonymous()
    /// let client = XPCClient.fromEndpoint(server.endpoint)
    /// ```
    ///
    /// > Important: No requests will be processed until ``XPCNonBlockingServer/start()`` or ``startAndBlock()`` is called.
    ///
    /// > Note: If you need this server to be communicated with by clients running in a different process, use ``makeAnonymous(clientRequirements:)``
    /// instead.
    public static func makeAnonymous() -> XPCServer & XPCNonBlockingServer {
        XPCAnonymousServer(messageAcceptor: SameProcessMessageAcceptor())
    }

    /// Creates a new anonymous server that accepts requests from clients which meet the security requirements.
    ///
    /// Only a client created from an anonymous server's endpoint can communicate with that server. Retrieve the ``XPCNonBlockingServer/endpoint``
    /// and send it across an existing XPC connection. Because other processes on the system can talk to an anonymous server, when making a server it is
    /// required that you specifiy the
    /// [requirements](https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/RequirementLang/RequirementLang.html)
    /// of any connecting clients:
    /// ```swift
    /// let reqString = "identifier \"com.example.AuthorizedClient\" and certificate leaf[subject.OU] = \"4L0ZG128MM\""
    /// var requirement: SecRequirement?
    /// if SecRequirementCreateWithString(reqString as CFString,
    ///                                   SecCSFlags(),
    ///                                   &requirement) == errSecSuccess,
    ///    let requirement = requirement {
    ///     let server = XPCServer.makeAnonymous(clientRequirements: [requirement])
    ///
    ///     <# configure and start server #>
    /// }
    /// ```
    ///
    /// > Important: No requests will be processed until ``XPCNonBlockingServer/start()`` or ``startAndBlock()`` is called.
    ///
    /// ## Requirements Checking
    /// On macOS 11 and later, requirement checking uses publicly documented APIs. On older versions of macOS, the private undocumented API
    /// `void xpc_connection_get_audit_token(xpc_connection_t, audit_token_t *)` will be used.  When requests are not accepted, if an
    /// error handler has been set then it is called with ``XPCError/insecure``.
    ///
    /// > Note: If you only need this server to be communicated with by clients running in the same process, use ``makeAnonymous()`` instead.
    ///
    /// - Parameters:
    ///   - clientRequirements: If a request is received from a client, it will only be processed if it meets one (or more) of these requirements.
    public static func makeAnonymous(clientRequirements: [SecRequirement]) -> XPCServer & XPCNonBlockingServer {
        XPCAnonymousServer(messageAcceptor: SecRequirementsMessageAcceptor(clientRequirements))
    }
    
    /// Provides a server for this helper tool if it was installed with
    /// [`SMJobBless`](https://developer.apple.com/documentation/servicemanagement/1431078-smjobbless).
    ///
    /// To successfully call this function the following requirements must be met:
    ///   - The launchd property list embedded in this helper tool must have exactly one entry for its `MachServices` dictionary
    ///   - The info property list embedded in this helper tool must have at least one element in its
    ///   [`SMAuthorizedClients`](https://developer.apple.com/documentation/bundleresources/information_property_list/smauthorizedclients)
    ///   array
    ///   - Every element in the `SMAuthorizedClients` array must be a valid security requirement
    ///     - To be valid, it must be creatable by
    ///     [`SecRequirementCreateWithString`](https://developer.apple.com/documentation/security/1394522-secrequirementcreatewithstring)
    ///
    /// Incoming requests will be accepted from clients that meet _any_ of the `SMAuthorizedClients` requirements.
    ///
    /// > Important: No requests will be processed until ``startAndBlock()`` or ``XPCNonBlockingServer/start()`` is called.
    ///
    /// - Throws: ``XPCError/misconfiguredBlessedHelperTool(_:)`` if the configuration does not match this function's requirements.
    /// - Returns: A server instance configured with the embedded property list entries.
    public static func forThisBlessedHelperTool() throws -> XPCServer & XPCNonBlockingServer {
        try XPCMachServer._forThisBlessedHelperTool()
    }
    
    /// Provides a server for this login item installed with
    /// [`SMLoginItemSetEnabled`](https://developer.apple.com/documentation/servicemanagement/1501557-smloginitemsetenabled).
    ///
    /// This function may successfully be called by both sandboxed and non-sandboxed login items. If this is a sandboxed login item, the
    /// [`com.apple.security.application-groups`](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_application-groups)
    /// entitlement must be present and one of the application groups must have the same team identifier as this login item. Both sandboxed and non-sandboxed
    /// apps must have a team identifier.
    ///
    /// Incoming requests will only be accepted from the main app or helper tools contained within the main app bundle. Additionally they must have the same team
    /// identifier as this login item.
    ///
    /// > Important: No requests will be processed until ``startAndBlock()`` or ``XPCNonBlockingServer/start()`` is called.
    ///
    /// - Returns: A server instance configured to communicate with its main containing app.
    public static func forThisLoginItem() throws -> XPCServer & XPCNonBlockingServer {
        try XPCMachServer._forThisLoginItem()
    }

    /// Provides a server for this XPC Mach service that accepts requests from clients which meet the security requirements.
    ///
    /// For the provided server to function properly, the caller must be an XPC Mach service.
    ///
    /// Because many processes on the system can talk to an XPC Mach service, when retrieving a server it is required that you specifiy the
    /// [requirements](https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/RequirementLang/RequirementLang.html)
    /// of any connecting clients:
    /// ```swift
    /// let reqString = "identifier \"com.example.AuthorizedClient\" and certificate leaf[subject.OU] = \"4L0ZG128MM\""
    /// var requirement: SecRequirement?
    /// if SecRequirementCreateWithString(reqString as CFString,
    ///                                   SecCSFlags(),
    ///                                   &requirement) == errSecSuccess,
    ///   let requirement = requirement {
    ///     let server = XPCServer.forThisMachService(named: "com.example.service",
    ///                                               clientRequirements: [requirement])
    ///
    ///    <# configure and start server #>
    /// }
    /// ```
    /// > Important: No requests will be processed until ``startAndBlock()`` or ``XPCNonBlockingServer/start()`` is called.
    ///
    /// ## Requirements Checking
    ///
    /// SecureXPC requires that a server for an XPC Mach service provide code signing requirements which define which clients are allowed to talk to it.
    ///
    /// On macOS 11 and later, requirement checking uses publicly documented APIs. On older versions of macOS, the private undocumented API
    /// `void xpc_connection_get_audit_token(xpc_connection_t, audit_token_t *)` will be used. When requests are not accepted, if an
    /// error handler has been set then it is called with ``XPCError/insecure``.
    ///
    /// - Parameters:
    ///   - named: The name of the Mach service this server should bind to.
    ///   - clientRequirements: If a request is received from a client, it will only be processed if it meets one (or more) of these requirements.
    /// - Throws: ``XPCError/conflictingClientRequirements`` if a server for this named service has previously been retrieved with different client
    ///           requirements.
    public static func forThisMachService(
        named machServiceName: String,
        clientRequirements: [SecRequirement]
    ) throws -> XPCServer & XPCNonBlockingServer {
        try XPCMachServer.getXPCMachServer(named: machServiceName,
                                           messageAcceptor: SecRequirementsMessageAcceptor(clientRequirements))
    }
}

// MARK: Helper functions

/// Tries to send a reply if the `reply` and `request` objects aren't nil.
fileprivate func maybeSendReply(_ reply: inout xpc_object_t?, request: Request?, connection: xpc_connection_t) throws {
    if var reply = reply, let request = request {
        try Response.encodeRequestID(request.requestID, intoReply: &reply)
        xpc_connection_send_message(connection, reply)
    }
}

// MARK: handler function wrappers

// These wrappers perform type erasure via their implemented protocols while internally maintaining type constraints
// This makes it possible to create heterogenous collections of them

fileprivate protocol XPCHandler {
    /// Whether as part of handling a request, an attempt should be made to create a reply.
    ///
    /// This doesn't necessarily mean the route actually has a reply type. This exists because for sequential reply types a reply should *not* be created as part
    /// of request handling; it may be created later if the sequence completes. XPC only allows a reply object to be created exactly once per request.
    var shouldCreateReply: Bool { get }
}

fileprivate extension XPCHandler {
    
    /// Validates that the incoming request matches the handler in terms of the presence of a message, reply, and/or sequential reply.
    ///
    /// The actual validation of the types themselves is performed as part of encoding/decoding and is intentionally not checked by this function.
    ///
    /// - Parameters:
    ///   - request: The incoming request.
    ///   - reply: The XPC reply object, if one exists.
    ///   - messageType: The parameter type of the registered handler, if applicable.
    ///   - replyType: The return type of the registered handler, if applicable.
    ///   - sequentialReplyType: The type used to provide sequential replies, if applicable.
    /// - Throws: If the check fails.
    func checkRequest(
        _ request: Request,
        reply: inout xpc_object_t?,
        messageType: Any.Type?,
        replyType: Any.Type?,
        sequentialReplyType: Any.Type?
    ) throws {
        var errorMessages = [String]()
        // Message
        if messageType == nil, request.containsPayload {
            errorMessages.append("Request had a message of type \(String(describing: request.route.messageType)), " +
                                 "but the handler registered with the server does not have a message parameter.")
        } else if let messageType = messageType, !request.containsPayload {
            errorMessages.append("Request did not contain a message, but the handler registered with the server has " +
                                 "a message parameter of type \(messageType).")
        }
        
        // Reply
        if replyType == nil, reply != nil && request.route.expectsReply {
            errorMessages.append("Request expects a reply of type \(String(describing: request.route.replyType)), " +
                                 "but the handler registered with the server has no return value.")
        } else if let replyType = replyType, reply == nil {
            errorMessages.append("Request does not expect a reply, but the handler registered with the server has a " +
                                 "return value of type \(replyType).")
        }
        
        // Reply sequence
        if sequentialReplyType != nil && request.route.sequentialReplyType == nil {
            errorMessages.append("Request expects a sequential reply of type " +
                                 String(describing: request.route.sequentialReplyType) + ", but the handler registered " +
                                 "with the server does not generate a sequential reply.")
        } else if sequentialReplyType == nil, let replySequenceType = request.route.sequentialReplyType {
            errorMessages.append("Request does not expect a sequential reply, but the handler registered with the " +
                                 "server has a sequential reply of type \(replySequenceType).")
        }
        
        if !errorMessages.isEmpty {
            throw XPCError.routeMismatch(request.route.pathComponents, errorMessages.joined(separator: "\n"))
        }
    }
}

// MARK: sync handler function wrappers

fileprivate protocol XPCHandlerSync: XPCHandler {
    func handle(
        request: Request,
        handleError: @escaping HandleError,
        connection: xpc_connection_t,
        reply: inout xpc_object_t?
    ) throws
}

fileprivate struct ConstrainedXPCHandlerWithoutMessageWithoutReplySync: XPCHandlerSync {
    var shouldCreateReply = true
    let handler: () throws -> Void
    
    func handle(
        request: Request,
        handleError: @escaping HandleError,
        connection: xpc_connection_t,
        reply: inout xpc_object_t?
    ) throws {
        try checkRequest(request, reply: &reply, messageType: nil, replyType: nil, sequentialReplyType: nil)
        try HandlerError.rethrow { try self.handler() }
    }
}

fileprivate struct ConstrainedXPCHandlerWithMessageWithoutReplySync<M: Decodable>: XPCHandlerSync {
    var shouldCreateReply = true
    let handler: (M) throws -> Void
    
    func handle(
        request: Request,
        handleError: @escaping HandleError,
        connection: xpc_connection_t,
        reply: inout xpc_object_t?
    ) throws {
        try checkRequest(request, reply: &reply, messageType: M.self, replyType: nil, sequentialReplyType: nil)
        let decodedMessage = try request.decodePayload(asType: M.self)
        try HandlerError.rethrow { try self.handler(decodedMessage) }
    }
}

fileprivate struct ConstrainedXPCHandlerWithoutMessageWithReplySync<R: Encodable>: XPCHandlerSync {
    var shouldCreateReply = true
    let handler: () throws -> R
    
    func handle(
        request: Request,
        handleError: @escaping HandleError,
        connection: xpc_connection_t,
        reply: inout xpc_object_t?
    ) throws {
        try checkRequest(request, reply: &reply, messageType: nil, replyType: R.self, sequentialReplyType: nil)
        let payload = try HandlerError.rethrow { try self.handler() }
        try Response.encodePayload(payload, intoReply: &reply!)
    }
}

fileprivate struct ConstrainedXPCHandlerWithMessageWithReplySync<M: Decodable, R: Encodable>: XPCHandlerSync {
    var shouldCreateReply = true
    let handler: (M) throws -> R
    
    func handle(
        request: Request,
        handleError: @escaping HandleError,
        connection: xpc_connection_t,
        reply: inout xpc_object_t?
    ) throws {
        try checkRequest(request, reply: &reply, messageType: M.self, replyType: R.self, sequentialReplyType: nil)
        let decodedMessage = try request.decodePayload(asType: M.self)
        let payload = try HandlerError.rethrow { try self.handler(decodedMessage) }
        try Response.encodePayload(payload, intoReply: &reply!)
    }
}

fileprivate struct ConstrainedXPCHandlerWithoutMessageWithSequentialReplySync<S: Encodable>: XPCHandlerSync {
    var shouldCreateReply = false
    let handler: (SequentialResultProvider<S>) -> Void
    
    func handle(
        request: Request,
        handleError: @escaping HandleError,
        connection: xpc_connection_t,
        reply: inout xpc_object_t?
    ) throws {
        try checkRequest(request, reply: &reply, messageType: nil, replyType: nil, sequentialReplyType: S.self)
        let sequenceProvider = SequentialResultProvider<S>(request: request,
                                                           errorHandler: handleError,
                                                           connection: connection)
        self.handler(sequenceProvider)
    }
}

fileprivate struct ConstrainedXPCHandlerWithMessageWithSequentialReplySync<M: Decodable, S: Encodable>: XPCHandlerSync {
    var shouldCreateReply = false
    let handler: (M, SequentialResultProvider<S>) -> Void
    
    func handle(
        request: Request,
        handleError: @escaping HandleError,
        connection: xpc_connection_t,
        reply: inout xpc_object_t?
    ) throws {
        try checkRequest(request, reply: &reply, messageType: M.self, replyType: nil, sequentialReplyType: S.self)
        let sequenceProvider = SequentialResultProvider<S>(request: request,
                                                           errorHandler: handleError,
                                                           connection: connection)
        let decodedMessage = try request.decodePayload(asType: M.self)
        self.handler(decodedMessage, sequenceProvider)
    }
}

// MARK: async handler function wrappers

@available(macOS 10.15.0, *)
fileprivate protocol XPCHandlerAsync: XPCHandler {
    func handle(
        request: Request,
        handleError: @escaping HandleError,
        connection: xpc_connection_t,
        reply: inout xpc_object_t?
    ) async throws
}

@available(macOS 10.15.0, *)
fileprivate struct ConstrainedXPCHandlerWithoutMessageWithoutReplyAsync: XPCHandlerAsync {
    var shouldCreateReply = true
    let handler: () async throws -> Void
    
    func handle(
        request: Request,
        handleError: @escaping HandleError,
        connection: xpc_connection_t,
        reply: inout xpc_object_t?
    ) async throws {
        try checkRequest(request, reply: &reply, messageType: nil, replyType: nil, sequentialReplyType: nil)
        try await HandlerError.rethrow { try await self.handler() }
    }
}

@available(macOS 10.15.0, *)
fileprivate struct ConstrainedXPCHandlerWithMessageWithoutReplyAsync<M: Decodable>: XPCHandlerAsync {
    var shouldCreateReply = true
    let handler: (M) async throws -> Void
    
    func handle(
        request: Request,
        handleError: @escaping HandleError,
        connection: xpc_connection_t,
        reply: inout xpc_object_t?
    ) async throws {
        try checkRequest(request, reply: &reply, messageType: M.self, replyType: nil, sequentialReplyType: nil)
        let decodedMessage = try request.decodePayload(asType: M.self)
        try await HandlerError.rethrow { try await self.handler(decodedMessage) }
    }
}

@available(macOS 10.15.0, *)
fileprivate struct ConstrainedXPCHandlerWithoutMessageWithReplyAsync<R: Encodable>: XPCHandlerAsync {
    var shouldCreateReply = true
    let handler: () async throws -> R
    
    func handle(
        request: Request,
        handleError: @escaping HandleError,
        connection: xpc_connection_t,
        reply: inout xpc_object_t?
    ) async throws {
        try checkRequest(request, reply: &reply, messageType: nil, replyType: R.self, sequentialReplyType: nil)
        let payload = try await HandlerError.rethrow { try await self.handler() }
        try Response.encodePayload(payload, intoReply: &reply!)
    }
}

@available(macOS 10.15.0, *)
fileprivate struct ConstrainedXPCHandlerWithMessageWithReplyAsync<M: Decodable, R: Encodable>: XPCHandlerAsync {
    var shouldCreateReply = true
    let handler: (M) async throws -> R
    
    func handle(
        request: Request,
        handleError: @escaping HandleError,
        connection: xpc_connection_t,
        reply: inout xpc_object_t?
    ) async throws {
        try checkRequest(request, reply: &reply, messageType: M.self, replyType: R.self, sequentialReplyType: nil)
        let decodedMessage = try request.decodePayload(asType: M.self)
        let payload = try await HandlerError.rethrow { try await self.handler(decodedMessage) }
        try Response.encodePayload(payload, intoReply: &reply!)
    }
}

@available(macOS 10.15.0, *)
fileprivate struct ConstrainedXPCHandlerWithoutMessageWithSequentialReplyAsync<S: Encodable>: XPCHandlerAsync {
    var shouldCreateReply = false
    let handler: (SequentialResultProvider<S>) async -> Void
    
    func handle(
        request: Request,
        handleError: @escaping HandleError,
        connection: xpc_connection_t,
        reply: inout xpc_object_t?
    ) async throws {
        try checkRequest(request, reply: &reply, messageType: nil, replyType: nil, sequentialReplyType: S.self)
        let sequenceProvider = SequentialResultProvider<S>(request: request,
                                                           errorHandler: handleError,
                                                           connection: connection)
        await self.handler(sequenceProvider)
    }
}

@available(macOS 10.15.0, *)
fileprivate struct ConstrainedXPCHandlerWithMessageWithSequentialReplyAsync<M: Decodable, S: Encodable>: XPCHandlerAsync {
    var shouldCreateReply = false
    let handler: (M, SequentialResultProvider<S>) async -> Void
    
    func handle(
        request: Request,
        handleError: @escaping HandleError,
        connection: xpc_connection_t,
        reply: inout xpc_object_t?
    ) async throws {
        try checkRequest(request, reply: &reply, messageType: M.self, replyType: nil, sequentialReplyType: S.self)
        let sequenceProvider = SequentialResultProvider<S>(request: request,
                                                           errorHandler: handleError,
                                                           connection: connection)
        let decodedMessage = try request.decodePayload(asType: M.self)
        await self.handler(decodedMessage, sequenceProvider)
    }
}

// MARK: Error Handler

typealias HandleError = (Error, Request?, xpc_connection_t?, inout xpc_object_t?) -> Void

/// Wrapper around an error handling closure to ensure there's only ever one error handler regardless of whether it's synchronous or asynchronous.
fileprivate enum ServerErrorHandler {
    case none
    case sync((XPCError) -> Void)
    case async((XPCError) async -> Void)
    
    func handle(_ error: XPCError) {
        switch self {
            case .none:
                break
            case .sync(let handler):
                handler(error)
            case .async(let handler):
                if #available(macOS 10.15, *) {
                    Task {
                        await handler(error)
                    }
                } else {
                    fatalError("async error handler was set on macOS prior to 10.15, this should not be possible")
                }
        }
    }
}

// MARK: Request Queue & RequestRunner

fileprivate class RequestQueue {
    /// All scheduling of requests is performed serially on this queue to ensure consistency
    private let serialCoordinationQueue = DispatchQueue(label: "RequestQueue - Serial Coordination Queue")
    
    /// Setting this on the `serialCoordinationQueue` allows for checking later if we're actually running on this queue.
    private let serialCoordinationKey = DispatchSpecificKey<String>()
    
    /// Requests which have not yet been dispatched to run asynchronously, either on a global dispatch queue or as a `Task`.
    private var pendingRequests = [RequestRunner]()
    
    /// Requests which have been dispatched to run asynchronously, either on a global dispatch queue or as a `Task`.
    ///
    /// Just because a request has been dispatched does not mean it has necessarily started running yet. Once it is done running, it will be removed from this set.
    private var inflightRequests = Set<RequestRunner>()
    
    /// The concurrency setting governing this queue. Accessed and updated by the ``XPCServer`` via the `set` and `get` functions to ensure these
    /// operations are run on the `serialCoordinationQueue`.
    private var handlerConcurrency: XPCServer.HandlerConcurrency
    
    init(handlerConcurrency: XPCServer.HandlerConcurrency) {
        self.handlerConcurrency = handlerConcurrency
        self.serialCoordinationQueue.setSpecific(key: self.serialCoordinationKey, value: "")
    }
    
    /// Asynchronously updates the concurrency setting and revaluates any pending requests as a result of this change.
    func setHandlerConcurrency(_ handlerConcurrency: XPCServer.HandlerConcurrency) {
        self.serialCoordinationQueue.async {
            if self.handlerConcurrency != handlerConcurrency {
                self.handlerConcurrency = handlerConcurrency
                self.reevaluatePendingRequests()
            }
        }
    }
    
    /// Synchronously returns the current concurrency setting.
    func getHandlerConcurrency() -> XPCServer.HandlerConcurrency {
        self.serialCoordinationQueue.sync {
            self.handlerConcurrency
        }
    }
    
    /// Enqueues the request and associated information at the end of the pending requests and revaluates all pending requests.
    ///
    /// - Parameters:
    ///   - request: A request to be processed.
    ///   - handler: A handler which should process this `request`.
    ///   - connection: A connection for which any replies must be sent over.
    ///   - errorHandler: A closure with which to provide any errors that occur while processing a request.
    func enqueue(
        request: Request,
        handler: XPCHandler,
        connection: xpc_connection_t,
        errorHandler: @escaping HandleError
    ) {
        self.serialCoordinationQueue.async {
            let runner = RequestRunner(request: request,
                                       handler: handler,
                                       connection: connection,
                                       handleError: errorHandler,
                                       onCompletion: self.finishedRunning(_:))
            // It's essential the request runner is always appended to the end so that ordering is maintained
            self.pendingRequests.append(runner)
            self.reevaluatePendingRequests()
        }
    }
    
    /// Must be called unconditionally by a request runner once it completes, whether in success or failure.
    private func finishedRunning(_ runner: RequestRunner) {
        self.serialCoordinationQueue.async {
            self.inflightRequests.remove(runner)
            self.reevaluatePendingRequests()
        }
    }
    
    /// Determines which pending requests, if any, should now be dispatched and does so.
    ///
    /// Specific behavior depends on the value of `handlerConcurrency`.
    private func reevaluatePendingRequests() {
        /// This must be called from the `serialCoordinationQueue`, but we don't want to wrap this in a call to
        /// `self.serialCoordinationQueue.async { ... }` because we want it to run immediately as part of the a larger operation such as setting
        /// `handlerConcurrency` or enqueuing a new request.
        guard DispatchQueue.getSpecific(key: serialCoordinationKey) != nil else {
            fatalError("reevaluatePendingRequests not called on \(serialCoordinationQueue)")
        }
        
        switch self.handlerConcurrency {
            // Run all pending requests
            case .concurrent:
                for runner in pendingRequests {
                    inflightRequests.insert(runner)
                    pendingRequests.removeAll{ $0 == runner }
                    runner.run()
                }
            // Run the first request for each connection that doesn't already have a request inflight
            case .serialPerClient:
                var inflightConnections = Set<Int>(inflightRequests.map{ xpc_hash($0.connection) })
                for runner in pendingRequests {
                    let connectionHash = xpc_hash(runner.connection)
                    if !inflightConnections.contains(connectionHash) {
                        inflightConnections.insert(connectionHash)
                        inflightRequests.insert(runner)
                        pendingRequests.removeAll{ $0 == runner }
                        runner.run()
                    }
                }
            // Run the first pending request if there is one and there are no inflight requests
            case .serialPerServer:
                if inflightRequests.isEmpty, !pendingRequests.isEmpty {
                    let runner = pendingRequests.removeFirst()
                    inflightRequests.insert(runner)
                    runner.run()
                }
        }
    }
}

/// Runs a `Request` for a provided `XPCHandler`.
///
/// The request is either run on a `DispatchQueue` or as a `Task` depending on if it's a `XPCHandlerSync` or `XPCHandlerAsync`.
fileprivate struct RequestRunner: Hashable {
    let request: Request
    let handler: XPCHandler
    let connection: xpc_connection_t
    let handleError: HandleError
    let onCompletion: (RequestRunner) -> Void
    
    func run() {
        if let handler = handler as? XPCHandlerSync {
            DispatchQueue.global().async {
                XPCRequestContext.setForCurrentThread(connection: connection, message: request.dictionary) {
                    defer { onCompletion(self) }
                    var reply = handler.shouldCreateReply ? xpc_dictionary_create_reply(request.dictionary) : nil
                    do {
                        try handler.handle(request: request,
                                           handleError: handleError,
                                           connection: connection,
                                           reply: &reply)
                        try maybeSendReply(&reply, request: request, connection: connection)
                    } catch {
                        var reply = handler.shouldCreateReply ? reply : xpc_dictionary_create_reply(request.dictionary)
                        handleError(error, request, connection, &reply)
                    }
                }
            }
        } else if #available(macOS 10.15.0, *), let handler = handler as? XPCHandlerAsync {
            XPCRequestContext.setForTask(connection: connection, message: request.dictionary) {
                Task {
                    defer { onCompletion(self) }
                    var reply = handler.shouldCreateReply ? xpc_dictionary_create_reply(request.dictionary) : nil
                    do {
                        try await handler.handle(request: request,
                                                 handleError: handleError,
                                                 connection: connection,
                                                 reply: &reply)
                        try maybeSendReply(&reply, request: request, connection: connection)
                    } catch {
                        var reply = handler.shouldCreateReply ? reply : xpc_dictionary_create_reply(request.dictionary)
                        handleError(error, request, connection, &reply)
                    }
                }
            }
        } else {
            fatalError("Non-sync handler for route \(request.route.pathComponents) was found, but only sync routes " +
                       "should be registrable on this OS version. Handler: \(handler)")
        }
    }
    
    static func == (lhs: RequestRunner, rhs: RequestRunner) -> Bool {
        lhs.request.requestID == rhs.request.requestID
    }
    
    func hash(into hasher: inout Hasher) {
        hasher.combine(self.request.requestID)
    }
}
