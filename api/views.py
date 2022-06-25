from django.shortcuts import render
from django.http import JsonResponse

# Create your views here.

def error_404(request, exception=None):
    # return render(request, 'error_404.html')
    return JsonResponse({
        'success': False, 
        'message': 'Page not found',
        'error': '404'
    })


def error_500(request):
    # return render(request, 'error_500.html')
    return JsonResponse({
        'success': False,
        'message': 'Internal server error',
        'error': '500'
    })


def test(request):
    return render(request, 'test.html')