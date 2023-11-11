<?php

namespace App\Http\Controllers;

use App\Models\User;
use App\Manager\Trait\CommonResponse;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;

class UserController extends Controller
{
    use CommonResponse;
    public function login(Request $request): JsonResponse
    {
        $validator = Validator::make($request->all(), [
            'email'    => 'required|string|email|max:255',
            'password' => 'required|string|min:8',
        ]);

        if ($validator->fails()) {
            $this->status_message = 'Failed! User login failed.';
            $this->status_code    = 422;
            $this->data           = $validator->errors();
            $this->status         = false;
            return $this->commonApiResponse();
        }

        $user = User::query()->where('email', $request->input('email'))->first();

        if (!$user || !Hash::check($request->password, $user->password)) {
            $this->status_message = 'Failed! User login failed.';
            $this->status_code    = $this->status_code_failed;
            $this->status         = false;
            return $this->commonApiResponse();
        }

        $token = $user->createToken('auth_token')->plainTextToken;

        $this->status_message = 'Success! User logged in successfully.';
        $this->status_code    = $this->status_code_success;
        $this->data           = [
            'token' => $token,
            'user'  => $user,
        ];
        $this->status         = true;
        return $this->commonApiResponse();
    }


    public function register(Request $request): JsonResponse
    {
        $validator = Validator::make($request->all(), [
            'name'                  => 'required|string|max:255',
            'email'                 => 'required|string|email|max:255|unique:users',
            'password'              => 'required|string|min:8',
            'password_confirmation' => 'required|string|min:8|same:password',
        ]);

        if ($validator->fails()) {
            $this->status_message = 'Failed! User registration failed.';
            $this->status_code    = 422;
            $this->errors         = $validator->errors();
            $this->status         = false;
            return $this->commonApiResponse();
        }

        try {
            $userData             = (new User())->prepareData($request);
            $token                = $userData->createToken('auth_token')->plainTextToken;
            $this->data           = [
                'token' => $token,
                'user'  => $userData,
            ];
            $this->status_message = 'Success! User registered successfully.';
            $this->status         = true;
            $this->commonApiResponse();
        } catch (\Throwable $e) {
            $this->status_message = 'Failed! User registration failed. ' . $e->getMessage();
            $this->status_code    = $this->status_code_failed;
            $this->status_class    = 'danger';
            $this->status         = false;

        }

        return $this->commonApiResponse();
    }

    public function logout(Request $request): JsonResponse
    {
        $request->user()->currentAccessToken()->delete();
        $this->status_message = 'Success! User logged out successfully.';
        $this->status_code    = $this->status_code_success;
        $this->status         = true;
        return $this->commonApiResponse();
    }

}
