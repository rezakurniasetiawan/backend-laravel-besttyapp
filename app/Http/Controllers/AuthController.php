<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use App\Models\User;

class AuthController extends Controller
{
    //Register User
    public function register(Request $request)
    {

        //Validate fields
        $attrs = $request->validate([
            'name' => 'required|string',
            'email' => 'required|email|unique:users,email',
            'password' => 'required|min:6|confirmed'
        ]);

        //Created User
        $user = User::create([
            'name' => $attrs['name'],
            'email' => $attrs['email'],
            'password' => bcrypt($attrs['password'])
        ]);

        //Return user & token in response
        return response([
            'user' => $user,
            'token' => $user->createToken('secret')->plainTextToken
        ], 200);
    }

    //Login user
    public function login(Request $request)
    {

        //Validate fields
        $attrs = $request->validate([
            'email' => 'required|email',
            'password' => 'required|min:6'
        ]);

        //Attmpt login
        if (!Auth::attempt($attrs)) {
            # code...
            return response([
                'message' => 'Invalid credentials.'
            ]);
        }


        //Return user & token in response
        return response([
            'status' => 200,
            'messages' => 'Successfully authentication',
            'user' => auth()->user(),
            'token' => $request->user()->createToken('secret')->plainTextToken
        ], 200);
    }

    //Logout User
    public function logout(Request $request)
    {
        $request->user()->tokens()->delete();
        return response([
            'message' => 'Logout Success.'
        ], 200);
    }

    //get user details
    public function user()
    {
        return response([
            'user' => auth()->user()
        ], 200);
    }
    // update user
    public function update(Request $request)
    {
        $attrs = $request->validate([
            'name' => 'required|string'
        ]);

        $image = $this->saveImage($request->image, 'profiles');

        auth()->user()->update([
            'name' => $attrs['name'],
            'image' => $image
        ]);

        return response([
            'message' => 'User updated.',
            'user' => auth()->user()
        ], 200);
    }
}
