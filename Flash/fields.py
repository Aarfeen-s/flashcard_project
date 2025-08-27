from djongo import models
from bson import ObjectId

class CustomObjectIdField(models.Field):
    """
    Custom field to allow multiple auto-generated ObjectId fields in a Django model.
    """
    def __init__(self, *args, **kwargs):
        kwargs['editable'] = False  # ObjectIds should not be editable
        kwargs.setdefault('default', ObjectId)
        super().__init__(*args, **kwargs)

    def contribute_to_class(self, cls, name, **kwargs):
        # Override to skip setting _meta.auto_field
        super().contribute_to_class(cls, name, **kwargs)
        # Do NOT set `cls._meta.auto_field` to avoid the assertion error
