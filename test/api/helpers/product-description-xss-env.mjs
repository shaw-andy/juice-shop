process.env.NODE_ENV = 'test'
// Forces the API-only XSS challenge on, including under Docker, the same way
// config/unsafe.yml does. node-config reads this before the app loads.
process.env.NODE_CONFIG = JSON.stringify({
  challenges: {
    safetyMode: 'disabled'
  }
})
