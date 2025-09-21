import { CogIcon } from '@heroicons/react/24/outline'

export default function Settings() {
  return (
    <div className="h-full overflow-auto">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <div className="mb-8">
          <h1 className="text-3xl font-bold text-white flex items-center">
            <CogIcon className="h-8 w-8 mr-3 text-blue-400" />
            Settings
          </h1>
          <p className="mt-2 text-gray-400">
            Configure your application preferences
          </p>
        </div>

        <div className="bg-gray-800 rounded-lg border border-gray-700 p-6">
          <p className="text-gray-300">Settings page coming soon...</p>
        </div>
      </div>
    </div>
  )
} 