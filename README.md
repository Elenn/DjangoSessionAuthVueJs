0. 
Django code
VueJs code (with axios)

Django Session Authentication
TODO: Vuex Store для переменной auth
----------------------------------------------
00. По образцу, но используя Django Session Authentication 

Django API Authentication using JWT Tokens
https://www.youtube.com/watch?v=PUzgZrS_piQ&list=PLlameCF3cMEthw3eWx4SvcCJ6A-leq7-n
https://github.com/scalablescripts/django-auth
C:\web\Django\django-auth-main 
*********************************************************************************************************************
                                   auth-session-My
*********************************************************************************************************************
0. Django
------------------------------------------
1. иду в папку, где я хочу создать проект
и создаю виртуальное окружение

C:\web\Django\auth-session-My
λ python -m venv venv
--------------------------------------
2. активирую виртуальное окружение
 
C:\web\Django\auth-session
.\venv\Scripts\activate 
----------------------------------------
3. Устанавливаю Django и djangorestframework

pip install Django
pip install djangorestframework 
pip install django-cors-headers 
----------------------------------------
4.
 pip freeze > requirements.txt
 
asgiref==3.7.2
Django==5.0
django-cors-headers==4.3.1
djangorestframework==3.14.0
pytz==2023.3.post1
sqlparse==0.4.4
typing_extensions==4.9.0
tzdata==2023.4
--------------------------------------
5. Создаю проект auth

C:\web\Django\auth-session-My
django-admin startproject auth
--------------------------------------
6. папку внутренную auth называют пакетом конфигурации
--------------------------------------
7. Запускаю сервер
- перехожу внутрь auth
cd auth

python manage.py runserver
--------------------------------------
8. Создаю внутри нашего auth новое апликейшен users
(то есть новую папку) - наш модуль

cd C:\web\Django\auth-session-My\auth
python manage.py startapp login_api
-------------------------------------------- 
9. Зарегистрировать новое приложение в auth/settings.py

C:\web\Django\auth-session\auth\auth\settings.py

INSTALLED_APPS = [
     . . .
     'corsheaders',
     'rest_framework',
     'users',
]
----------------------------------------- 
10.
python.exe -m pip install --upgrade pip 
pip freeze > requirements.txt
----------------------------------------
11.
MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'corsheaders.middleware.CorsMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
	. . .
---------------------------------------
12.
INSTALLED_APPS = [
    # ...
    'django.contrib.sessions',
------------------------------------------
13.
python manage.py migrate
------------------------------------------
14. регистрирую модель в admin

from django.contrib import admin
from .models import MyModel

admin.site.register(MyModel)
------------------------------------------
15.
# views.py

from rest_framework.views import APIView 
from django.contrib.auth import authenticate, login, logout
from django.http import JsonResponse
from django.views.decorators.csrf import ensure_csrf_cookie
from rest_framework.response import Response
from rest_framework.exceptions import AuthenticationFailed
from rest_framework import viewsets 
from rest_framework.permissions import IsAuthenticated
from rest_framework.authentication import SessionAuthentication, BasicAuthentication
from .serializers import PostSerializer
from .models import Post 

class ShowPostsViewSet(viewsets.ModelViewSet): 
    serializer_class = PostSerializer
    queryset = Post.objects.all()  
    permission_classes = [IsAuthenticated]
    authentication_classes = (SessionAuthentication,) 
 
class RegisterView(APIView):
    def post(self, request):
       pass

class LoginView(APIView):
    def post(self, request):
         
        password = request.data['password']
        username = request.data['username']

        user = authenticate(request, username=username, password=password)

        if user is not None:
            login(request, user)
            return JsonResponse({'message': 'Login successful'})
        else:
            return JsonResponse({'message': 'Login failed'}, status=401) 
        

class LogoutView(APIView):
    def post(self, request): 
        logout(request) 
        response = Response() 
        response.data = {
            'message': 'Logout successful'
        }
        return response
        #return JsonResponse({'message': 'Logout successful'})
		
def logout_view(request):
    logout(request)
    return JsonResponse({'message': 'Logout successful'})		
---------------------------------------------------
16. serializers.py

C:\web\Django\auth-session-My\auth\login_api\serializers.py

from rest_framework import serializers
from .models import Post


class PostSerializer(serializers.ModelSerializer):
    class Meta:
        model = Post
        fields = ['id', 'title', 'content'] 
-----------------------------------------------------
17. models.py

C:\web\Django\auth-session\auth\users\models.py
 
from django.db import models 
 
class Post(models.Model):
    title = models.CharField(max_length=255)
    content = models.CharField(max_length=255)
----------------------------------------------------
18. 
python manage.py makemigrations
python manage.py migrate	
------------------------------------------------- 
19. в раутере auth/urls.py добавляю path 

C:\web\Django\auth-session-My\auth\auth\urls.py 

from django.contrib import admin
from django.urls import path, include

urlpatterns = [
    path('admin/', admin.site.urls),
    path('apilogin/', include('login_api.urls')),
]
-----------------------------------------------
20.
C:\web\Django\auth-session-My\auth\login_api\urls.py

from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import RegisterView, LoginView, LogoutView, ShowPostsViewSet, logout_view 
 
router = DefaultRouter()
router.register(r'posts', ShowPostsViewSet, basename='posts') 

urlpatterns = [
    path('', include(router.urls)),
    path('register/', RegisterView.as_view()), 
    path('login/', LoginView.as_view()), 
    path('logout/', logout_view), 
]

http://127.0.0.1:8000/apilogin/register/	
http://127.0.0.1:8000/apilogin/login/	
http://127.0.0.1:8000/apilogin/logout/
http://127.0.0.1:8000/apilogin/posts/
----------------------------------------------------
21.
python manage.py runserver 
----------------------------------------------------
22. Создаю superuser

cd C:\web\Django\djangoapi

python manage.py createsuperuser

 
----------------------------------------------------
23. логинюсь в http://127.0.0.1:8000/admin/
- создаю новый post
---------------------------------------------- 
24. открываю Postman 
 
раню POST запрос к http://127.0.0.1:8000/api/login/
header -> Content-Type: application/json

Body -> raw 

{
    "username":"xx", 
    "password":"xxx"
}

получаю ответ

{
    "message": "Login successful"
}

- впечатываю в браузере 
http://127.0.0.1:8000/api/login/
- теперь могу видить в правом верхнем углу lena@aa.com

- теперь в Application -> Cookies вижу sessionid


- http://127.0.0.1:8000/api/posts/
-> Network -> Headers -> Cookies - есть sessionid
csrftoken=nU1VZk7eWdMIVHNeRC0Y6wL4P6Pso5kW; sessionid=qaqydz77ecz9pvu8qszhz3l0pj8c57s6
-------------------------------------------------
25. Cоздаю класс с permissions - IsAuthenticated

Создаю модель

id
title
content

from django.db import models 
 
class Post(models.Model):
    title = models.CharField(max_length=255)
    content = models.CharField(max_length=255) 
------------------------------------------------------
26. serializers.py

from rest_framework import serializers
from .models import Post


class PostSerializer(serializers.ModelSerializer):
    class Meta:
        model = Post
        fields = ['id', 'title', 'content'] 

-------------------------------------------------------
27. view.py

from rest_framework.views import APIView 
from django.contrib.auth import authenticate, login, logout
from django.http import JsonResponse 
from rest_framework.response import Response
from rest_framework.exceptions import AuthenticationFailed
from rest_framework import viewsets 
from rest_framework.permissions import IsAuthenticated
from .serializers import PostSerializer
from .models import Post 

class ShowPostsViewSet(viewsets.ModelViewSet): 
    serializer_class = PostSerializer
    queryset = Post.objects.all()  
    permission_classes = [IsAuthenticated]	
----------------------------------------------------
28. urls

from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import RegisterView, LoginView, LogoutView, ShowPostsViewSet

router = DefaultRouter()
router.register(r'posts', ShowPostsViewSet, basename='posts') 

urlpatterns = [
    path('', include(router.urls)),
    path('register/', RegisterView.as_view()), 
    path('login/', LoginView.as_view()),
    path('logout/', LogoutView.as_view()),
]

http://127.0.0.1:8000/api/register
http://127.0.0.1:8000/api/login
http://127.0.0.1:8000/api/logout
http://127.0.0.1:8000/api/posts
-----------------------------------------------
29.
После того, как послали правильную комбинацию login/password
на сервенен создается session_id и он записывается в базу данных для конкретного user_id

--------------------------------------------
30. Открываю SQLiteStudio и смотрю на таблицы, которые создались

даунложу клиента SQLiteStudio для sqlite servera
даунложу файл sqlitestudio-3.3.3.zip 
c https://sqlitestudio.pl/ 
 
C:\web\Django\sqlitestudio-3.3.3\SQLiteStudio\SQLiteStudio.exe

SELECT id,
       password,
       last_login,
       is_superuser,
       username,
       last_name,
       email,
       is_staff,
       is_active,
       date_joined,
       first_name
  FROM auth_user;

SELECT session_key,
       session_data,
       expire_date
  FROM django_session;
-----------------------------------------------------
31.

path('api/v1/drf-auth/'), include('rest_framework.urls')

include('rest_framework.urls') TypeError: _path() missing 1 required positional argument: 'view'
 
------------------------------------------------
32.

REST_FRAMEWORK = {
    'DEFAULT_PERMISSION_CLASSES': [
        'rest_framework.permissions.AllowAny',
    ],
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'rest_framework.authentication.SessionAuthentication',
    ]
} 

. . . 

CSRF_COOKIE_HTTPONLY = False
SESSION_COOKIE_HTTPONLY = True

SESSION_ENGINE = 'django.contrib.sessions.backends.db'
 

CORS_ALLOWED_ORIGINS = [
    "http://localhost:8080",  # Add your frontend origin(s)
    # ... other allowed origins ...
]

CSRF_TRUSTED_ORIGINS = ['http://localhost:8080']

CORS_ALLOW_CREDENTIALS = True 
 
CSRF_COOKIE_SAMESITE = None  
 
******************************************************************************************************************
                                                 Vue
										auth-session-vue-My		 
******************************************************************************************************************* 
1. Проверяю, что бэкэнд ранится с предыдущим работающим фронтэндом
C:\web\Django\auth-session\auth-session-vue
-------------------------------------------------  
2. Создаю проект

vue create auth-session-vue-my
-> manually selected features
-> Router
-> 3
-> Use history mode for router Y
------------------------------------------------------
3. Раню проект

npm run serve
------------------------------------------------------
4.
npm install axios  
npm install js-cookie 
--------------------------------------------------------
5. bootstrap.min.css

C:\web\Django\auth-session\auth-session-vue\public\index.html 

 <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.0.0-beta1/dist/css/bootstrap.min.css" rel="stylesheet"
          integrity="sha384-giJF6kkoqNQ00vy+HMDP7azOuL0xtbfIcaT9wjKHr8RbDVddVHyTfAAsrekwKmP1" crossorigin="anonymous">
-----------------------------------------------------
6.
C:\web\Django\auth-session\auth-session-vue\src\pages\Main.vue

- Создаю папку page
- Создаю файл myMain.vue в папке pages

<template>
    <div class="my-main">
        <p v-if="message=='Login successful'">Welcome {{username}}!</p>
        <h1>Session Authentication. VueJs & Django Rest Framework</h1>

        <div class="row" v-if="loginLoginSuccessfulMessage!='Login successful'">
            <div class="col-md-2 ms-5">
                <input v-model="inputUserName" type="email" class="form-control" placeholder="Email" required>
                <input v-model="inputPassword" type="password" class="form-control" placeholder="Password" required>

                <button class="w-100 btn btn-lg btn-primary" @click="login">Login</button>
            </div>
        </div>
        <br />
        <div v-if="loginLoginSuccessfulMessage=='Login successful'">
            <button @click="logout">Logout</button>
        </div>
        <button @click="showPosts">Show Posts</button> 

        <div class="post-list" v-for="post in posts" :key="post">
            {{post.title}}: {{post.content}}
        </div>
    </div>
</template>

<script>
    import axios from 'axios';
    import Cookies from 'js-cookie';
    export default {
        name: 'MyMain',
        data() {
            return {
                loginLoginSuccessfulMessage: '',
                username: '',
                posts: [],
                inputUserName: '',
                inputPassword: '',
            }
        },
        mounted() {
            var token = Cookies.get('csrftoken');
            if (token && this.loginLoginSuccessfulMessage == '') {
                this.logout();
            }
        },
        methods: {
            showPosts() {
                axios.get('http://localhost:8000/apilogin/posts/', { withCredentials: true, })
                    .then(response => {
                        this.posts = response.data
                        console.log(response.data);
                    })
                    .catch(error => {
                        console.error('Error:', error);
                    });
            }, 
            login() {
                axios.post('http://localhost:8000/apilogin/login/', {
                    //username: this.inputUserName,
                    //password: this.inputPassword
            
                }, { withCredentials: true })
                    .then(response => {
                        this.loginLoginSuccessfulMessage = response.data.message
                        console.log(response.data);
                    })
                    .catch(error => {
                        console.error('Error:', error);
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
                        this.loginLoginSuccessfulMessage = ''
                        console.log(response.data);
                    })
                    .catch(error => {
                        console.error('Error:', error);
                    });
            }
        }
    }
</script>

<style scoped>
    .post-list {
        text-align: left;
        margin: 60px 0 0 100px;
    }
</style>  
-----------------------------------------------------
7. Создаю в папке router
- В файле index.js в папке router

C:\web\Django\auth-session\auth-session-vue\src\router\router.js

import { createRouter, createWebHistory } from 'vue-router'
import MyMain from "@/pages/myMain";

const routes = [
    { path: '/main', component: MyMain },
]

const router = createRouter({
  history: createWebHistory(process.env.BASE_URL),
  routes
})

export default router

-----------------------------------------------------
8. регистрирую роутер в main.js
C:\web\Django\auth-session\auth-session-vue\src\main.js

import { createApp } from 'vue'
import App from './App.vue'
import router from './router'

createApp(App)
    .use(router)
    .mount('#app')

-----------------------------------------------------
9. Вижу, что уже добавлено 

C:\web\Django\auth-session\auth-session-vue 

npm install --save vue-router

появляется:

"dependencies": {
    . . .
    "vue-router": "^4.0.3"
  },
-----------------------------------------------------
10. Добавляю в App.vue - <router-view></router-view>

<template>
  <nav>
      <router-link to="/main">myMain</router-link>
  </nav>
  <router-view/>
</template>

<style>
#app {
  font-family: Avenir, Helvetica, Arial, sans-serif;
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
  text-align: center;
  color: #2c3e50;
}

nav {
  padding: 30px;
}

nav a {
  font-weight: bold;
  color: #2c3e50;
}

nav a.router-link-exact-active {
  color: #42b983;
}
</style> 
-----------------------------------------------------
11.
npm run serve

http://localhost:8080/ 
------------------------------------------------------
*******************************************************************************************************************
                                     vue store
*******************************************************************************************************************
1. 
"vuex": "^4.1.0" 
npm install vuex --save
------------------------------
2. Nav.vue

C:\web\Django\auth-session-My\auth-session-vue-my\src\components\Nav.vue

<template>
  <nav class="navbar navbar-expand-md navbar-dark bg-dark mb-4">
    <div class="container-fluid">
      <router-link to="/" class="navbar-brand">Home</router-link>

      <div>
        <ul class="navbar-nav me-auto mb-2 mb-md-0" v-if="!auth">
          <li class="nav-item">
            <router-link to="/login" class="nav-link">Login</router-link>
          </li>
          <li class="nav-item">
            <router-link to="/register" class="nav-link">Register</router-link>
          </li>
        </ul>

        <ul class="navbar-nav me-auto mb-2 mb-md-0" v-if="auth">
          <li class="nav-item">
              <router-link to="/login" class="nav-link" @click="logout">Logout</router-link>
          </li>
        </ul>
      </div>
    </div>
  </nav>
</template>

<script lang="ts">
import {computed} from 'vue';
import {useStore} from "vuex";

export default {
  name: "Nav",
  setup() {
      const store = useStore();

      const auth = computed(() => store.state.authenticated)

      const logout = async () => {
          try {
              await fetch('http://localhost:8000/api/logout', {
                  method: 'POST',
                  headers: { 'Content-Type': 'application/json' },
                  credentials: 'include',
              });
              await store.dispatch('setAuth', false);
          } catch (e) {
              console.log('error to log out') 
          }
    }

    return {
      auth,
      logout
    }
  }
}
</script>
------------------------------------
3. Создаю папку store и файл index.js в ней

------------------------------------
4. myMain.vue

C:\web\Django\auth-session-My\auth-session-vue-my\src\pages\myMain.vue

<template>
  {{ message }}
</template>

<script lang="ts">
import {onMounted, ref} from 'vue';
import {useStore} from "vuex";

export default {
  name: "Home",
  setup() {
    const message = ref('You are not logged in!');
    const store = useStore();

    onMounted(async () => {
      try {
        const response = await fetch('http://localhost:8000/api/user', {
          headers: {'Content-Type': 'application/json'},
          credentials: 'include'
        });

        const content = await response.json();

        message.value = `Hi ${content.name}`;

        await store.dispatch('setAuth', true);
      } catch (e) {
        await store.dispatch('setAuth', false);
      }
    }); 

    return {
      message
    }
  }
}
</script>
---------------------------------
5. App.vue

C:\web\Django\auth-session-My\auth-session-vue-my\src\App.vue

<template> 

    <nav class="navbar navbar-expand-md navbar-dark bg-dark mb-4">
        <ul class="navbar-nav me-auto mb-2 mb-md-0">
            <li class="nav-item">
                <router-link to="/" class="nav-link">Home</router-link>
            </li>
            <li class="nav-item">
                <router-link to="/main" class="nav-link">Session Authentication</router-link>
            </li> 
        </ul>
        <ul class="navbar-nav">
            <li class="nav-item">
                <router-link to="/login" class="nav-link">Login</router-link>
            </li>
            <li class="nav-item">
                <router-link to="/register" class="nav-link">Register</router-link>
            </li>
            <li class="nav-item">
                <router-link to="/login" class="nav-link" @click="logout">Logout</router-link>
            </li>
        </ul>
    </nav> 
     
    <router-view />
</template> 
------------------------------
6. 
store не закончила
------------------------------
7.	
C:\web\Django\auth-session-My\auth-session-vue-my\src\pages\Login.vue

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
export default {
    name: "LoginView",
    data() {
        return {
            loginLoginSuccessfulMessage: '',
            username: '', 
            inputUserName: '',
            inputPassword: '',
        }
    },
    methods: {
        login() {
            //const store = useStore(); 
            axios.post('http://localhost:8000/apilogin/login/', {
                //username: this.inputUserName,
                //password: this.inputPassword 
            }, { withCredentials: true })
                .then(response => {
                    this.loginLoginSuccessfulMessage = response.data.message
                    this.$router.push('posts')  
                    //store.dispatch('setAuth', true);

                    console.log(response.data);
                })
                .catch(error => {
                    console.error('Error:', error);
                    //store.dispatch('setAuth', false);

                });
        },
    } 
    }
</script>
----------------------------------
8.
import { createRouter, createWebHistory } from 'vue-router'
import MyMain from "@/pages/myMain";

const routes = [
    { path: '/main', component: MyMain },
    { path: '/login', component: LoginView },
]

const router = createRouter({
  history: createWebHistory(process.env.BASE_URL),
  routes
})

export default router
-------------------------------------------
9. topNav.vue

C:\web\Django\auth-session-My\auth-session-vue-my\src\components\topNav.vue
 
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
                <router-link to="/login" class="nav-link">Login</router-link>
            </li>
            <li class="nav-item">
                <router-link to="/login" class="nav-link" @click="logout">Logout</router-link>
            </li>
        </ul>
    </nav>
</template>

<script>
import axios from 'axios';
import Cookies from 'js-cookie'; 
export default {
    name: "topNav",
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
                    this.loginLoginSuccessfulMessage = ''
                    console.log(response.data);
                })
                .catch(error => {
                    console.error('Error:', error);
                });
        }
    }
}
</script>
------------------------------------------
10. PostView.vue

C:\web\Django\auth-session-My\auth-session-vue-my\src\pages\PostView.vue

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
-------------------------------------
11.
import { createRouter, createWebHistory } from 'vue-router' 
import LoginView from "@/pages/LoginView";
import PostView from "@/pages/PostView";

const routes = [ 
    { path: '/login', component: LoginView },
    { path: '/posts', component: PostView },
]

const router = createRouter({
  history: createWebHistory(process.env.BASE_URL),
  routes
})

export default router
---------------------------------------------
12. store:
- создаю папку store и файл index.js в ней

import { Commit, createStore } from 'vuex'

export default createStore({
    state: {
        authenticated: false
    }, 
    actions: {
        setAuth: ({ commit }: { commit: Commit }, auth: boolean) => commit('SET_AUTH', auth)
    },
    mutations: {
        SET_AUTH: (state: { authenticated: boolean }, auth: boolean) => state.authenticated = auth
    },
    modules: {}
})
---------------------------------------------
13.

main.js 

import { createApp } from 'vue'
import App from './App.vue'
import router from './router'
import store from './store'

createApp(App)
    .use(store)
    .use(router)
    .mount('#app')
 
--------------------------------------
16. store

C:\web\Django\auth-session-My\auth-session-vue-my\src\store\index.js

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
----------------------------------------
17. this.$store.state.authenticated;
    this.$store.dispatch('setAuth', false);

C:\web\Django\auth-session-My\auth-session-vue-my\src\components\topNav.vue

	<li class="nav-item">
		<router-link to="/login" class="nav-link" v-if="!auth">Login</router-link>
	</li>
	<li class="nav-item">
		<router-link to="/login" class="nav-link" @click="logout"  v-if="auth">Logout</router-link>
	</li>
	. . .		
    computed: {
        auth() {
            return this.$store.state.authenticated;
        },
    },
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
-------------------------------------------
18.	this.$store.dispatch('setAuth', true);

C:\web\Django\auth-session-My\auth-session-vue-my\src\pages\LoginView.vue

methods: {
        login() { 
            axios.post('http://localhost:8000/apilogin/login/', {
                //username: this.inputUserName,
                //password: this.inputPassword 
            }, { withCredentials: true })
                .then(response => {
                    this.loginLoginSuccessfulMessage = response.data.message

                    this.$store.dispatch('setAuth', true);
                    console.log(response.data); 

                    this.$router.push('posts')   
                })
                .catch(error => {
                    console.error('Error:', error);
                    this.$store.dispatch('setAuth', true);

                });
        },
    } 
-------------------------------------------
**********************************************************************************************************************
                                           Выставляю на git
**********************************************************************************************************************
1. https://github.com/login 
-----------------------------------
2. https://github.com -> New
DjangoSessionAuthVueJs
-----------------------------------
3. Clone
 
Visual Studio  
-> Clone Repository ->

https://github.com/Elenn/DjangoSessionAuthVueJs
в папку C:\web\Django\DjangoSessionAuthenticationVueJs
---------------------------
4. 	Cкопировала папку (без venv и node_modules)

C:\web\Django\auth-session-My
в
C:\web\Django\DjangoSessionAuthenticationVueJs
-----------------------------------
5. login with brauser
-----------------------------------
 





















 