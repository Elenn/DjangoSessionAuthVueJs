<template>
    <div class="row justify-content-md-center">
        <div class="col-md-8">
            <div class="col-md-2">
                <button class="w-100 btn btn-lg btn-primary" @click="showPosts">Show Posts</button>
            </div> 

            <div class="post-list" v-for="post in posts" :key="post">
                {{post.title}}: {{post.content}}
            </div> 
            <span>{{errorMessage}}</span>
        </div>
    </div>
</template>

<script>

import axios from 'axios';
export default {
    name: "LoginView",
    data() {
        return {
            posts: [],
            errorMessage:''
        }
    },
    methods: {
        showPosts() {
            this.errorMessage = ''
            axios.get('http://localhost:8000/apilogin/posts/', { withCredentials: true, })
                .then(response => {
                    this.posts = response.data
                    console.log(response.data);
                })
                .catch(error => {
                    this.errorMessage = ''
                    if (error.message == 'Request failed with status code 403')
                        this.errorMessage = 'You do not have access to see this data. Please login.'
                    console.error('Error:', error);
                });
        }, 
    }
    }
</script>