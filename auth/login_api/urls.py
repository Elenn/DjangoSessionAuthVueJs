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