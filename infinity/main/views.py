from django.shortcuts import render

# Create your views here.
#admin panel
  
def admindashboard(request):
    
    return render(request,"admin panel/dashboard.html")  

def admin_addblog(request):
    return render(request,"admin panel/Add_blog.html")

def admin_addbrand(request):
    return render(request,"admin panel/Add_brand.html")

def admin_addcategory(request):
    return render(request,"admin panel/Add_category.html")

def admin_addportfolio(request):
    return render(request,"admin panel/Add_portfolio.html")

def admin_addservice(request):

    return render(request,"admin panel/add_service.html")

def admin_add_FAQ(request):
    return render(request,"admin panel/add_FAQ.html")

def admin_blog_manage(request):
    return render(request,"admin panel/blog_manage.html")

def admin_brand_manage(request):
    return render(request,"admin panel/brand_manage.html")

def admin_category_manage(request):
    return render(request,"admin panel/category_manage.html")

def admin_faq_manage(request):
    return render(request,"admin panel/faq_manage.html")


def admin_forget(request):
    return render(request,"admin panel/forget.html")

def admin_login(request):
    return render(request,"admin panel/login.html")

def admin_portfolio_manage(request):
    return render(request,"admin panel/portfolio_manage.html")

def admin_PrivacyAndPolicy(request):
    return render(request,"admin panel/PrivacyAndPolicy.html")

def admin_reset_password(request):
    return render(request,"admin panel/reset_password.html")

def admin_service_manage(request):

    return render(request,"admin panel/service_manage.html")

def admin_termscondition(request):
    return render(request,"admin panel/terms-condition.html")

def admin_edit_termscondition(request):
    return render(request,"admin panel/edit_TandC.html")

def admin_edit_privacyPolicy(request):
    return render(request,"admin panel/edit_privacyandpolicy.html")


def admin_change_password(request):
    return render(request,"admin panel/change_password.html")



# view and edit views

#edit
def admin_edit_blog(request ,id):
    return render(request,"admin panel/edit_blog.html", context={"id":id})
def admin_edit_brand(request,id):
    return render(request,"admin panel/edit_brand.html", context={"id":id})
def admin_edit_category(request,id):
    return render(request,"admin panel/edit_category.html", context={"id":id})
def admin_edit_faq(request,id):
    return render(request,"admin panel/edit_faq.html", context={"id":id})
def admin_edit_portfolio(request,id):
    return render(request,"admin panel/edit_portfolio.html", context={"id":id})
def admin_edit_service(request,id):
    return render(request,"admin panel/service_edit.html" , context={"id":id})
#views
# def admin_view_blog(request):
#     return render(request,"admin panel/blog_view.html")
def brand_view(request,id):
    return render(request,"admin panel/view_brand.html",{'id':id})
def admin_view_category(request,id):
    return render(request,"admin panel/category_view.html",{'id':id})
def faq_view(request,id):
    return render(request,"admin panel/view_faq.html",{'id':id})
def portfolio_view(request,id):
    return render(request,"admin panel/portfolio_view.html",{'id':id})
def service_view(request, id):
    return render(request, "admin panel/service_view.html", context={"id": id})
def blog_view(request,id):
    return render(request,"admin panel/blog_view.html",{'id':id})
# def admin_view_service(request,id):
#     return render(request,"admin panel/view_service.html",{"id":id})

def verifyOTP(request):
    return render(request,"admin panel/cp_otp_sended.html")

def forget_otp(request):
    return render(request,"admin panel/forgot_otp.html")

def editProfile(request):
    return render(request,"admin panel/edit_profile.html")

def reset_password(request):
    return render(request,"admin panel/reset_password.html")

def change_verify(request):
    return render(request,"admin panel/cp_otp_verify.html")