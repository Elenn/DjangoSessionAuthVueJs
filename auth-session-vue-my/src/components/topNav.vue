<template>
    <nav class="navbar navbar-expand-md navbar-dark bg-dark mb-4">
        <ul class="navbar-nav me-auto mb-2 mb-md-0">
            <li class="nav-item">
                <router-link to="/" class="nav-link">Home</router-link>
            </li>
            <li class="nav-item">
                <router-link to="/posts" class="nav-link">Posts</router-link>
            </li>
        </ul>
        <ul class="navbar-nav">
            <li class="nav-item">
                <router-link to="/login" class="nav-link" v-if="!auth">Login</router-link>
            </li>
            <li class="nav-item">
                <router-link to="/login" class="nav-link" @click="logout"  v-if="auth">Logout</router-link>
            </li>
        </ul> 
    </nav>
</template>

<script>
import axios from 'axios';
import Cookies from 'js-cookie'; 
export default {
    name: "topNav",
    computed: {
        auth() {
            return this.$store.state.authenticated;
        },
    },
    methods: {
        logout() {
            axios.post('http://localhost:8000/apilogin/logout/', {
            }, {
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': Cookies.get('csrftoken')
                },
                withCredentials: true,
            })
                .then(response => { 
                    this.$store.dispatch('setAuth', false);
                    console.log(response.data);
                })
                .catch(error => {
                    console.error('Error:', error);
                });
        }
    }
}
</script>
