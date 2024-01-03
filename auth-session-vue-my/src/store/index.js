import { createStore } from 'vuex' 
const store = createStore({ 
    state: {
        authenticated: false
    }, 
    getters: {},
    mutations: {
        SET_AUTH(state, payload) {
            state.authenticated = payload
        }
    },
    actions: {
        setAuth(context, payload) {
            context.commit('SET_AUTH', payload)
        } 
    }, 
})

export default store;