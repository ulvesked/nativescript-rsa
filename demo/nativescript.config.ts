import { NativeScriptConfig } from '@nativescript/core'

export default {
  id: 'org.nativescript.nativescript-rsa.demo',
  appPath: 'app',
  appResourcesPath: 'app/App_Resources',
  android: {
    v8Flags: '--expose_gc',
    markingMode: 'none',
    requireModules: {
      0: 'nativescript-rsa',
    },
  },
} as NativeScriptConfig
