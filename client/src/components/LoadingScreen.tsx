import React from 'react'

const LoadingScreen: React.FC = () => {
  return (
    <div className="fixed inset-0 bg-gray-900 flex items-center justify-center z-50">
      <div className="text-center">
        {/* Main loading animation */}
        <div className="relative mb-8">
          <div className="w-16 h-16 border-4 border-gray-700 border-t-blue-500 rounded-full animate-spin mx-auto"></div>
          <div className="w-12 h-12 border-4 border-transparent border-t-blue-400 rounded-full animate-spin absolute top-2 left-1/2 transform -translate-x-1/2"></div>
        </div>

        {/* Logo/Brand */}
        <div className="mb-6">
          <h1 className="text-2xl font-bold text-white mb-2">
            🛡️ Cybersecurity Web App
          </h1>
          <p className="text-gray-400 text-sm">
            Professional Security Testing Platform
          </p>
        </div>

        {/* Loading text with animation */}
        <div className="mb-8">
          <p className="text-gray-300 text-lg font-medium">
            Initializing security tools
            <span className="animate-pulse">...</span>
          </p>
        </div>

        {/* Progress indicators */}
        <div className="space-y-3 w-64 mx-auto">
          <div className="flex items-center space-x-3 text-sm">
            <div className="w-2 h-2 bg-green-500 rounded-full animate-pulse"></div>
            <span className="text-gray-400">Loading SQLMap integration</span>
          </div>
          <div className="flex items-center space-x-3 text-sm">
            <div className="w-2 h-2 bg-blue-500 rounded-full animate-pulse animation-delay-200"></div>
            <span className="text-gray-400">Establishing secure connection</span>
          </div>
          <div className="flex items-center space-x-3 text-sm">
            <div className="w-2 h-2 bg-purple-500 rounded-full animate-pulse animation-delay-400"></div>
            <span className="text-gray-400">Initializing terminal interface</span>
          </div>
          <div className="flex items-center space-x-3 text-sm">
            <div className="w-2 h-2 bg-yellow-500 rounded-full animate-pulse animation-delay-600"></div>
            <span className="text-gray-400">Loading security modules</span>
          </div>
        </div>

        {/* Matrix-style background effect */}
        <div className="fixed inset-0 pointer-events-none opacity-10 z-[-1]">
          <div className="absolute top-0 left-0 w-full h-full overflow-hidden">
            {Array.from({ length: 20 }).map((_, i) => (
              <div
                key={i}
                className="absolute text-green-400 text-sm font-mono animate-matrix"
                style={{
                  left: `${Math.random() * 100}%`,
                  animationDelay: `${Math.random() * 2}s`,
                  animationDuration: `${3 + Math.random() * 2}s`,
                }}
              >
                {Math.random() > 0.5 ? '1' : '0'}
              </div>
            ))}
          </div>
        </div>

        {/* Version info */}
        <div className="absolute bottom-8 left-1/2 transform -translate-x-1/2">
          <p className="text-gray-500 text-xs">
            Version {import.meta.env.VITE_APP_VERSION || '1.0.0'}
          </p>
        </div>
      </div>

      <style>{`
        @keyframes matrix {
          0% {
            transform: translateY(-100vh);
            opacity: 0;
          }
          10% {
            opacity: 1;
          }
          90% {
            opacity: 1;
          }
          100% {
            transform: translateY(100vh);
            opacity: 0;
          }
        }

        .animate-matrix {
          animation: matrix 4s linear infinite;
        }

        .animation-delay-200 {
          animation-delay: 200ms;
        }

        .animation-delay-400 {
          animation-delay: 400ms;
        }

        .animation-delay-600 {
          animation-delay: 600ms;
        }
      `}</style>
    </div>
  )
}

export default LoadingScreen 