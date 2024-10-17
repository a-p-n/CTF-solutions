//import * as Vue from 'vue' // in Vue 3
import axios from 'axios'
import VueAxios from 'vue-axios'
/**
 * main.ts
 *
 * Bootstraps Vuetify and other plugins then mounts the App`
 */


// Plugins
import { registerPlugins } from '@/plugins'

// Components
import App from './App.vue'

// Composables
import { createApp } from 'vue'

const app = createApp(App)

registerPlugins(app)

app.use(VueAxios, axios)
app.mount('#app')
