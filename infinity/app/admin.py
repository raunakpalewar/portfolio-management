from django.contrib import admin
from app.models import Myuser,static_content,FAQ,ServiceManagementModel,Portfolio_Management_model,Blog_Management_model,Category_management_model,Brand_management_model
class MyuserAdmin(admin.ModelAdmin):
    list_display = ['id','email', 'name', 'role', 'is_active', 'is_staff', 'is_superuser', 'created_at']
admin.site.register(Myuser, MyuserAdmin)

class static_contentAdmin(admin.ModelAdmin):
    list_display = ['title']
admin.site.register(static_content, static_contentAdmin)

class FAQ_Admin(admin.ModelAdmin):
    list_display = ['sr_no','question','created_at']
admin.site.register(FAQ, FAQ_Admin)
admin.site.register([ServiceManagementModel,Portfolio_Management_model,Blog_Management_model,Category_management_model,Brand_management_model])
