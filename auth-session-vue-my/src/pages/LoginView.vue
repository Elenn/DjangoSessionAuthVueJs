<template>
    <div class="row justify-content-md-center">
        <div class="col-md-3">  
            <h1 class="h3 mb-3 fw-normal">Please sign in</h1>

            <input v-model="inputUserName" type="email" class="form-control" placeholder="Email" required>
            <input v-model="inputPassword" type="password" class="form-control" placeholder="Password" required>

            <button class="w-100 btn btn-lg btn-primary" @click="login">Login</button>
        </div>
    </div>
</template>

<script> 
import axios from 'axios'; 
import Cookies from 'js-cookie';
export default {
    name: "LoginView",
    data() {
        return {  
            inputUserName: '',
            inputPassword: '',
        }
    },
    methods: {
        login() { 
            this.logout();
            axios.post('http://localhost:8000/apilogin/login/', {
                username: this.inputUserName,
                password: this.inputPassword 
            }, { withCredentials: true })
                .then(response => {  
                    this.$store.dispatch('setAuth', true);
                    console.log(response.data); 

                    this.$router.push('posts')   
                })
                .catch(error => {
                    console.error('Error:', error);
                    this.$store.dispatch('setAuth', false);

                });
        },
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
        },
    } 
 }
</script>