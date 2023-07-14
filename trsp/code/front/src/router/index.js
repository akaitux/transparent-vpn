import {createRouter, createWebHistory} from 'vue-router'
import Home from '../views/Home.vue'
import AuthLogin from '../views/Login.vue'

const routes = [
  {
    path: '/',
    name: 'home',
    component: Home
  },
  {
    path: '/auth/login',
    name: 'auth.login',
    component: AuthLogin
  }
]

const router = createRouter({
  mode: createWebHistory(),
  routes
})

export default router
