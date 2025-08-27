from rest_framework.permissions import BasePermission

class IsOwner(BasePermission):
    def has_object_permission(self, request, view, obj):
        # Check if the question belongs to the logged-in user
        return obj.created_by == request.user
