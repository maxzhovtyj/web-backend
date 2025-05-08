from rest_framework import generics, permissions
from django.contrib.auth.models import User
from .serializers import RegisterSerializer, UserSerializer
from drf_spectacular.utils import extend_schema

class RegisterView(generics.CreateAPIView):
    queryset = User.objects.all()
    serializer_class = RegisterSerializer

class ProfileView(generics.RetrieveAPIView):
    serializer_class = UserSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_object(self):
        return self.request.user

from rest_framework import viewsets
from .models import Todo
from .serializers import TodoSerializer

class TodoViewSet(viewsets.ModelViewSet):
    serializer_class = TodoSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        return Todo.objects.filter(user=self.request.user)

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)

from django.http import JsonResponse

def root_view(request):
    return JsonResponse({"message": "Welcome to the TODO API"})


from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from django.contrib.auth import login, authenticate, logout
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django.contrib.auth.models import User
from .models import Todo

def signup_view(request):
    if request.user.is_authenticated:
        return redirect('home')
    if request.method == 'POST':
        form = UserCreationForm(request.POST)
        if form.is_valid():
            user = form.save()
            login(request, user)
            return redirect('home')
    else:
        form = UserCreationForm()
    return render(request, 'main/signup.html', {'form': form})

def signin_view(request):
    if request.user.is_authenticated:
        return redirect('home')
    if request.method == 'POST':
        form = AuthenticationForm(request, data=request.POST)
        if form.is_valid():
            user = form.get_user()
            login(request, user)
            return redirect('home')
    else:
        form = AuthenticationForm()
    return render(request, 'main/signin.html', {'form': form})

@login_required
def home_view(request):
    todos = Todo.objects.filter(user=request.user)
    return render(request, 'main/home.html', {'todos': todos})

@login_required
def profile_view(request):
    return render(request, 'main/profile.html', {'user': request.user})

def signout_view(request):
    logout(request)
    return redirect('signin')


from django.views.decorators.http import require_POST
from django.shortcuts import get_object_or_404
from .models import Todo

from rest_framework.decorators import api_view
from rest_framework.response import Response

@extend_schema(
    methods=["POST"],
    description="Create a new TODO item.",
    responses={201: None}
)
@api_view(['POST'])
@login_required
def add_todo(request):
    title = request.POST.get('title')
    if title:
        Todo.objects.create(user=request.user, title=title)
    return redirect('home')

@extend_schema(
    methods=["POST"],
    description="Delete a TODO item by ID.",
    responses={204: None}
)
@api_view(['POST'])
@login_required
def delete_todo(request, pk):
    todo = get_object_or_404(Todo, pk=pk, user=request.user)
    todo.delete()
    return redirect('home')


from django.views.decorators.http import require_POST

@extend_schema(
    methods=["POST"],
    description="Mark a TODO as completed.",
    responses={200: None}
)
@api_view(['POST'])
@login_required
def complete_todo(request, pk):
    todo = get_object_or_404(Todo, pk=pk, user=request.user)
    todo.completed = True
    todo.save()
    return redirect('home')