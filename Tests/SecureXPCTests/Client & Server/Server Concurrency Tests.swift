//
//  Server Concurrency Tests.swift
//  
//
//  Created by Josh Kaplan on 2022-05-11
//

import Foundation
import XCTest
import SecureXPC

class ServerConcurrencyTests: XCTestCase {
    
    func testSerialPerServer() async throws {
        let server = XPCServer.makeAnonymous()
        server.handlerConcurrency = .serialPerServer
        let client = XPCClient.forEndpoint(server.endpoint)
        
        let route1 = XPCRoute.named("1").withReplyType(Int.self)
        let route1Sleep = 0.1
        server.registerRoute(route1) {
            Thread.sleep(forTimeInterval: route1Sleep)
            
            return 1
        }
        let route2 = XPCRoute.named("2").withReplyType(Int.self)
        let route2Sleep = 0.2
        server.registerRoute(route2) {
            Thread.sleep(forTimeInterval: route2Sleep)
            
            return 2
        }
        server.start()
        
        let start = CFAbsoluteTimeGetCurrent()
        async let return1 = client.send(to: route1)
        async let return2 = client.send(to: route2)
        let _ = await [try return1, try return2]
        let duration = CFAbsoluteTimeGetCurrent() - start
        
        let minimumHandlerExecutionTime = route1Sleep + route2Sleep
        if duration < minimumHandlerExecutionTime {
            XCTFail("Should have taken at least \(minimumHandlerExecutionTime), took \(duration) instead")
        }
    }
    
    func testSerialPerClient_1Client() async throws {
        let server = XPCServer.makeAnonymous()
        server.handlerConcurrency = .serialPerClient
        let client = XPCClient.forEndpoint(server.endpoint)
        
        let route1 = XPCRoute.named("1").withReplyType(Int.self)
        let route1Sleep = 0.1
        server.registerRoute(route1) {
            Thread.sleep(forTimeInterval: route1Sleep)
            
            return 1
        }
        let route2 = XPCRoute.named("2").withReplyType(Int.self)
        let route2Sleep = 0.2
        server.registerRoute(route2) {
            Thread.sleep(forTimeInterval: route2Sleep)
            
            return 2
        }
        server.start()
        
        let start = CFAbsoluteTimeGetCurrent()
        async let return1 = client.send(to: route1)
        async let return2 = client.send(to: route2)
        let _ = await [try return1, try return2]
        let duration = CFAbsoluteTimeGetCurrent() - start
        
        let minimumHandlerExecutionTime = route1Sleep + route2Sleep
        if duration < minimumHandlerExecutionTime {
            XCTFail("Should have taken at least \(minimumHandlerExecutionTime), took \(duration) instead")
        }
    }
    
    func testSerialPerClient_2Clients() async throws {
        let server = XPCServer.makeAnonymous()
        server.handlerConcurrency = .serialPerClient
        let client1 = XPCClient.forEndpoint(server.endpoint)
        let client2 = XPCClient.forEndpoint(server.endpoint)
        
        let route1 = XPCRoute.named("1").withReplyType(Int.self)
        let route1Sleep = 0.1
        server.registerRoute(route1) {
            Thread.sleep(forTimeInterval: route1Sleep)
            
            return 1
        }
        let route2 = XPCRoute.named("2").withReplyType(Int.self)
        let route2Sleep = 0.2
        server.registerRoute(route2) {
            Thread.sleep(forTimeInterval: route2Sleep)
            
            return 2
        }
        server.start()
        
        let start = CFAbsoluteTimeGetCurrent()
        async let return1 = client1.send(to: route1)
        async let return2 = client2.send(to: route2)
        let _ = await [try return1, try return2]
        let duration = CFAbsoluteTimeGetCurrent() - start
        
        let totalHandlerExecutionTime = route1Sleep + route2Sleep
        if duration > totalHandlerExecutionTime {
            XCTFail("Should have taken less than \(totalHandlerExecutionTime), took \(duration) instead")
        }
    }
    
    func testConcurrent() async throws {
        let server = XPCServer.makeAnonymous()
        server.handlerConcurrency = .concurrent
        let client = XPCClient.forEndpoint(server.endpoint)
        
        let route1 = XPCRoute.named("1").withReplyType(Int.self)
        let route1Sleep = 0.1
        server.registerRoute(route1) {
            Thread.sleep(forTimeInterval: route1Sleep)
            
            return 1
        }
        let route2 = XPCRoute.named("2").withReplyType(Int.self)
        let route2Sleep = 0.2
        server.registerRoute(route2) {
            Thread.sleep(forTimeInterval: route2Sleep)
            
            return 2
        }
        server.start()
        
        let start = CFAbsoluteTimeGetCurrent()
        async let return1 = client.send(to: route1)
        async let return2 = client.send(to: route2)
        let _ = await [try return1, try return2]
        let duration = CFAbsoluteTimeGetCurrent() - start
        
        let totalHandlerExecutionTime = route1Sleep + route2Sleep
        if duration > totalHandlerExecutionTime {
            XCTFail("Should have taken less than \(totalHandlerExecutionTime), took \(duration) instead")
        }
    }
}
