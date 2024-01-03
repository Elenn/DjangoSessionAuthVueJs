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