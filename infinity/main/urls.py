from django.urls import path
from main.views import *
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    # admin panel urls
    path("",admin_login,name="admin_login"),
    path('admin_dashboard',admindashboard,name="admin_dashboard"),
    path("forget",admin_forget,name="forget"),
    path("privacypolicy",admin_PrivacyAndPolicy,name="privacypolicy"),
    path("reset_password",admin_reset_password,name="reset_password"),
    path("termscondition",admin_termscondition,name="termscondition"),
    path("change_password",admin_change_password,name="change_password"),
    path("verifyOtp", verifyOTP, name="verifyOtp"),
    path("change_verify",change_verify,name="change_verify"),
    path('edit_profile', editProfile, name="edit_profile"),
    path('forget_otp',forget_otp,name="forget_otp"),
    path('reset_password',reset_password,name="reset_password"),
    
    #admin add urls
    path("addblog",admin_addblog,name="addblog"),
    path("addbrand",admin_addbrand,name="addbrand"),
    path("addcategory",admin_addcategory,name="addcategory"),
    path("addportfolio",admin_addportfolio,name="addportfolio"),
    path("addservice",admin_addservice,name="addservice"),
    path("addFAQ",admin_add_FAQ,name="addFAQ"),
    path("edit_termscondition",admin_edit_termscondition,name="edit_termscondition"),
    path("edit_privacy&policy",admin_edit_privacyPolicy,name="edit_privacyandpolicy"),
    
    #admin manage urls
    path("blog_manage",admin_blog_manage,name="blog_manage"),
    path("brand_manage",admin_brand_manage,name="brand_manage"),
    path("category_manage",admin_category_manage,name="category_manage"),
    path("faq_manage",admin_faq_manage,name="faq_manage"),
    path("service_manage",admin_service_manage,name="service_manage"),
    path("portfolio_manage",admin_portfolio_manage,name="portfolio_manage"),

    # view pages
    # path("service_view/<int:id>",service_view, name="service_view"),
    # path("/service_view/<int:id>/",service_view, name="service_view"),

    #edit urls    
    path("edit_blog/<int:id>",admin_edit_blog,name="edit_blog"),
    path("edit_brand/<int:id>",admin_edit_brand,name="edit_brand"), 
    path("edit_category/<int:id>", admin_edit_category,name="edit_category"), 
    path("edit_faq/<int:id>", admin_edit_faq,name="edit_faq"), 
    path("edit_portfolio/<int:id>", admin_edit_portfolio,name="edit_portfolio"), 
    path("edit_service/<int:id>",admin_edit_service,name="edit_service"),

     #views urls        
    path("view_blog/<int:id>",blog_view,name="view_blog"), 
    path("view_brand/<int:id>",brand_view,name="view_brand"), 
    path("view_category/<int:id>",admin_view_category,name="view_category"), 
    path("view_faq/<int:id>", faq_view,name="view_faq"), 
    path("view_portfolio/<int:id>", portfolio_view,name="view_portfolio"), 
    path("view_service/<int:id>",service_view,name="view_service"),

] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)+static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
