from api.models.user import User

from django.http import JsonResponse
from ApiChat.settings import SECRET_KEY

import jwt  # pip install PyJWT
import hashlib
import json
import datetime


def register(request):
    if request.method == "POST":
        DATA = json.loads(request.body)
        try:
            username = DATA["username"]
            email = DATA["email"]
            password = DATA["password"]
            first_name = DATA["first_name"]
            last_name = DATA["last_name"]
        except KeyError:
            return JsonResponse(
                {
                    "success": False,
                    "message": "Missing required fields",
                    "error": "400",
                },
                status=400,
            )
        if (
            User.objects.filter(username=username).exists()
            or User.objects.filter(email=email).exists()
        ):
            return JsonResponse(
                {
                    "success": False,
                    "message": "User already exists with this username or email",
                    "error": "409",
                },
                status=409,
            )

        user = User.objects.create(
            username=username,
            email=email,
            password=hashlib.sha256(password.encode("utf-8")).hexdigest(),
            first_name=first_name,
            last_name=last_name,
        )

        token = jwt.encode(
            {
                "uid": user.id,
                "exp": datetime.datetime.utcnow() + datetime.timedelta(days=7),
                "iat": datetime.datetime.utcnow(),
            },
            SECRET_KEY,
            algorithm="HS256",
        )

        if type(token) == bytes:
            token = token.decode("utf-8")

        return JsonResponse(
            {
                "success": True,
                "message": "User created successfully",
                "user": user.toJSON(),
                "token": token,
            },
            status=201,
        )


def login(request):
    if request.method == "POST":
        DATA = json.loads(request.body)
        try:
            username = DATA["username"]
            password = DATA["password"]
        except KeyError as e:
            return JsonResponse(
                {
                    "success": False,
                    "message": "Missing required fields",
                    "error": "400",
                },
                status=400,
            ) 
        try:
            user = (
                User.objects.get(username=username)
                or User.objects.get(email=username)
                or User.objects.get(phone=username)
                or User.objects.get(id=username)
            )
        except User.DoesNotExist:
            return JsonResponse(
                {"success": False, "message": "User does not exist", "error": "404"},
                status=404,
            )

        if not user.checkPassword(password):
            return JsonResponse(
                {"success": False, "message": "Invalid password", "error": "401"},
                status=401,
            )

        token = jwt.encode(
            {
                "uid": user.id,
                "exp": datetime.datetime.utcnow() + datetime.timedelta(days=7),
                "iat": datetime.datetime.utcnow(),
            },
            SECRET_KEY,
            algorithm="HS256",
        )

        if type(token) == bytes:
            token = token.decode("utf-8")

        return JsonResponse(
            {
                "success": True,
                "message": "User logged in successfully",
                "user": user.toJSON(),
                "token": token,
            },
            status=200,
        )


def edit_profile(request):
    if request.method == "POST":
        DATA = json.loads(request.body)

        try:
            token = request.headers.get("Authorization").split(" ")[1]
            uid = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])["uid"]
            user = User.objects.get(id=uid)
        except jwt.ExpiredSignatureError:
            return JsonResponse(
                {"success": False, "message": "Token expired", "error": "401"},
                status=401,
            )
        except jwt.InvalidTokenError:
            return JsonResponse(
                {"success": False, "message": "Invalid token", "error": "401"},
                status=401,
            )
        except KeyError:
            return JsonResponse(
                {"success": False, "message": "Missing token", "error": "400"},
                status=400,
            )

        if "password" not in DATA or not user.checkPassword(password):
            return JsonResponse(
                {"success": False, "message": "Invalid password", "error": "401"},
                status=401,
            )

        user.username = DATA["username"] if "username" in DATA else user.username
        user.email = DATA["email"] if "email" in DATA else user.email
        user.first_name = (
            DATA["first_name"] if "first_name" in DATA else user.first_name
        )
        user.last_name = DATA["last_name"] if "last_name" in DATA else user.last_name
        if "new_password" in DATA:
            user.password = hashlib.sha256(
                DATA["new_password"].encode("utf-8")
            ).hexdigest()

        user.save()

        return JsonResponse(
            {
                "success": True,
                "message": "User updated successfully",
                "user": user.toJSON(),
            },
            status=200,
        )
