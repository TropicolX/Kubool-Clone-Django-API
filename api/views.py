from rest_framework_simplejwt.tokens import RefreshToken
from api.models import CustomUser
from .serializers import MessageSerializer

from rest_framework.permissions import IsAuthenticated
from rest_framework.views import APIView
from rest_framework.exceptions import NotFound, ParseError
from rest_framework.response import Response
from rest_framework import serializers
from rest_framework import status

from django.core.exceptions import ValidationError
from django.contrib.auth.password_validation import validate_password
from django.contrib.auth.hashers import check_password
from django.db.utils import IntegrityError


class SignUp(APIView):
    ''' For Sign up user '''

    def post(self, request, *args, **kwargs):
        try:
            username = request.data['username']
            password = request.data['password']

            validate_password(password=password)

            user = CustomUser.objects.create_user(
                username=username, password=password)

            refresh = RefreshToken.for_user(user)

            return Response({'detail': 'User created successfully', 'tokens': {'refresh': str(refresh), 'access': str(refresh.access_token)}})

        except KeyError:
            raise ParseError(
                {"detail": "Provide a valid username and password"})

        except ValidationError as e:
            raise ParseError({'detail': list(e)})

        except IntegrityError:
            raise serializers.ValidationError(
                {'detail': "A user with this username already exists"})

        except Exception as ex:
            print(ex)  # remove for production
            raise serializers.ValidationError(
                {'detail': "Can't complete this request. Ensure the data posted is in the correct format."})


class Login(APIView):
    ''' Login for user'''

    def post(self, request, *args, **kwargs):
        try:
            username = request.data['username']
            password = request.data['password']
            user = CustomUser.objects.get(username=username)
            if not check_password(password, user.password):
                raise ParseError({"detail": "Incorrect password"})

        except CustomUser.DoesNotExist:
            raise NotFound({"detail": "Username not found"})

        except KeyError:
            raise ParseError(
                {"detail": "Provide 'username' and 'password'"})

        except Exception as ex:
            print(ex)  # remove for production
            raise ParseError(
                {'detail': "Can't complete this request. Ensure the data posted is in the correct format."})

        refresh = RefreshToken.for_user(user)

        return Response({'tokens': {'refresh': str(refresh), 'access': str(refresh.access_token)}})


class ChangePassword(APIView):
    """ For Changing user password """
    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        user = request.user
        try:
            password = request.data['password']

            validate_password(password)

            user.set_password(password)
            user.save()

            return Response({'detail': 'User password updated successfully'})

        except KeyError:
            raise ParseError({"detail": "Provide a valid password"})

        except ValidationError as e:
            raise ParseError({'detail': list(e)})

        except Exception as ex:
            print(ex)  # remove for production
            raise ParseError(
                {'detail': "Can't complete this request. Ensure the data posted is in the correct format."})


class DeleteUser(APIView):
    """ For deleting User account"""
    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        user = request.user
        user.delete()

        return Response({'detail': "User deleted successfully"})


class CheckUser(APIView):
    """ view for verifying if user or not """

    def post(self, request, *args, **kwargs):
        try:
            share_code = kwargs['share_code']
            user = CustomUser.objects.get(share_code=share_code)
        except CustomUser.DoesNotExist:
            raise NotFound(
                detail="Sorry no user with these credidentials exists")
        except KeyError:
            raise ParseError({"detail": "Provide a user share code"})

        return Response({'detail': 'User exists', 'username': user.username})


class AllAnonMessages(APIView):
    """ Return all Anonymous messages """
    permission_classes = [IsAuthenticated, ]

    def get(self, request, *args, **kwargs):
        user = request.user
        messages = MessageSerializer(user.messages.all(), many=True)

        return Response({'messages': messages.data})


class GetUser(APIView):
    '''Get username and share code using valid access token'''
    permission_classes = [IsAuthenticated, ]

    def post(self, request, *args, **kwargs):
        user = request.user
        return Response({'data': {"username": user.username, "share_code": user.share_code}})


class BlacklistTokenView(APIView):
    '''Blacklist refresh token and log out'''

    def post(self, request):
        try:
            refresh_token = request.data["refresh_token"]
            token = RefreshToken(refresh_token)
            token.blacklist()

            return Response({'detail': "User logged out successfully"})

        except KeyError:
            raise ParseError({"detail": "Provide a refresh token"})

        except Exception as e:
            return Response(status=status.HTTP_400_BAD_REQUEST)
