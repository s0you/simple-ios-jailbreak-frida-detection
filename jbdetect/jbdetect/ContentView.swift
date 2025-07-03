//
//  ContentView.swift
//  jbdetect
//
//  Created by Wahyu Wira on 15/06/25.
//

import SwiftUI


struct ContentView: View {
    @State private var isJailbroken: Bool? = nil
    @State private var isFrida: Bool? = nil
    @State private var isGGRunning: Bool? = nil

    var body: some View {
        VStack(spacing: 20) {
            if let isJailbroken = isJailbroken {
                Text(isJailbroken ? "⚠️ Device is Jailbroken!" : "✅ Device is not Jailbroken")
                    .font(.title)
                    .foregroundColor(isJailbroken ? .red : .green)
            } else {
                Text("Jailbreak Checking...")
                    .font(.title2)
            }
            
            if let isFrida = isFrida {
                Text(isFrida ? "⚠️ Frida Detected!" : "✅ Frida is not Running")
                    .font(.title)
                    .foregroundColor(isFrida ? .red : .green)
            } else {
                Text("Frida Checking...")
                    .font(.title2)
            }
        }
        .onAppear {
            isJailbroken = Init.isDeviceJailbroken()
            isFrida = Init.isFridaRunning()
            isGGRunning = Init.isGodGameRunning()
        }
        .padding()
    }
}

#Preview {
    ContentView()
}
