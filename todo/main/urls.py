from django.urls import path, include
from .views import root_view, RegisterView, ProfileView, TodoViewSet, todos
from rest_framework.routers import DefaultRouter
from .views import add_todo, delete_todo, complete_todo

router = DefaultRouter()
router.register(r'todos', TodoViewSet, basename='todo')

urlpatterns = [
    path('auth/register/', RegisterView.as_view(), name='register'),
    path('auth/profile/', ProfileView.as_view(), name='profile'),
    # path('', include(router.urls)),
]

from django.urls import path, include
from .views import signup_view, signin_view, home_view, profile_view, signout_view

urlpatterns += [
    path('', home_view, name='home'),
    path('signup/', signup_view, name='signup'),
    path('signin/', signin_view, name='signin'),
    path('signout/', signout_view, name='signout'),
    path('profile/', profile_view, name='profile'),
    path('todo/all/', todos, name='todos'),
    path('todo/add/', add_todo, name='add_todo'),
    path('todo/delete/<int:pk>/', delete_todo, name='delete_todo'),
    path('todo/complete/<int:pk>/', complete_todo, name='complete_todo'),
]
