from django.urls import path
from .views import UserViewSet, UserDetail, TaskCreateView, ChangePasswordView, ResetPasswordView, UserTasksView, \
    TasksByStatusView, TasksByCategoryView, TasksByPriorityView, UserTaskDetailView, TaskUpdateView, TaskDeleteView, \
    CategoryViewSet, PriorityViewSet, CustomAuthToken, LogoutView, UserCreate

urlpatterns = [
    path('register/', UserCreate.as_view(), name='user-register'),
    path('api-token-auth/', CustomAuthToken.as_view(), name='api-token-auth'),
    path('api/logout/', LogoutView.as_view(), name='logout'),

    path('users/', UserViewSet.as_view(), name='user-list'),  # все пользователи GET http://127.0.0.1:8000/api/v1/users/
    path('users/<int:pk>/', UserDetail.as_view(), name='user-detail'),  # GET http://127.0.0.1:8000/api/v1/users/3/
    path('change-password/', ChangePasswordView.as_view(), name='change_password'),
    # POST http://127.0.0.1:8000/api/v1/change-password/
    path('reset-password/', ResetPasswordView.as_view(), name='reset_password'),
    # POST http://127.0.0.1:8000/api/v1/reset-password/

    path('create_task/', TaskCreateView.as_view(), name='create_task'),
    # POST http://127.0.0.1:8000/api/v1/create_task/
    path('tasks/', UserTasksView.as_view(), name='user_tasks'),  # GET http://127.0.0.1:8000/api/v1/create_task/
    path('tasks/status/', TasksByStatusView.as_view(), name='tasks_by_status'),
    # GET http://127.0.0.1:8000/api/v1/tasks/status/?status=pending
    path('tasks/category/', TasksByCategoryView.as_view(), name='tasks_by_category'),
    # GET http://127.0.0.1:8000/api/v1/tasks/category/?category=1
    path('tasks/priority/', TasksByPriorityView.as_view(), name='tasks_by_priority'),
    # GET http://127.0.0.1:8000/api/v1/tasks/priority/?priority=1
    path('tasks/<int:pk>/', UserTaskDetailView.as_view(), name='user_task_detail'),
    # GET http://127.0.0.1:8000/api/v1/tasks/1/
    path('tasks/<int:pk>/update/', TaskUpdateView.as_view(), name='task_update'),
    # PUT http://127.0.0.1:8000/api/v1/tasks/1/update/
    path('tasks/<int:pk>/delete/', TaskDeleteView.as_view(), name='task_delete'),
    # DELETE http://127.0.0.1:8000/api/v1/tasks/1/delete/

    path('categories/', CategoryViewSet.as_view({'post': 'create'}), name='category-create'),
    path('categories/<int:pk>/',
         CategoryViewSet.as_view({
             'get': 'retrieve',
             'put': 'update',
             'patch': 'partial_update',
             'delete': 'destroy'}),
         name='category-detail'),

    path('priorities/', PriorityViewSet.as_view({'post': 'create'}), name='priority-create'),
    path('priorities/<int:pk>/', PriorityViewSet.as_view({
        'get': 'retrieve',
        'put': 'update',
        'patch': 'partial_update',
        'delete': 'destroy'
    }), name='priority-detail'),
]
