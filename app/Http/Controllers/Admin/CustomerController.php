<?php

namespace App\Http\Controllers\Admin;

use App\CentralLogics\Helpers;
use App\Http\Controllers\Controller;
use App\Models\EMoney;
use App\Models\Transaction;
use App\Models\User;
use Brian2694\Toastr\Facades\Toastr;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;

class CustomerController extends Controller
{

    public function index()
    {
        return view('admin-views.customer.index');
    }

    public function store(Request $request)
    {
        $request->validate([
            'f_name' => 'required',
            'l_name' => 'required',
            'image' => 'required',
            'email' => '',
            'phone' => 'required|unique:users|min:5|max:20',
            'gender' => 'required',
            'occupation' => 'required',
            'password' => 'required|min:4|max:4',
        ], [
            'password.min' => 'Password must contain 4 characters',
            'password.max' => 'Password must contain 4 characters',
        ]);

        DB::transaction(function () use ($request) {
            $user = new User();
            $user->f_name = $request->f_name;
            $user->l_name = $request->l_name;
            $user->image = Helpers::upload('customer/', 'png', $request->file('image'));
            $user->email = $request->email;
            $user->phone = $request->phone;
            $user->gender = $request->gender;
            $user->occupation = $request->occupation;
            $user->password = bcrypt($request->password);
            $user->type = 2;    //['Admin'=>0, 'Agent'=>1, 'Customer'=>2]
            $user->referral_id = $request->referral_id ?? null;
            $user->save();

            $user->find($user->id);
            $user->unique_id = $user->id . mt_rand(1111, 99999);
            $user->save();

            $emoney = new EMoney();
            $emoney->user_id = $user->id;
            $emoney->save();
        });

        Toastr::success(\App\CentralLogics\translate('Customer Added Successfully!'));
        return back();
    }

    public function customer_list(Request $request)
    {
        $query_param = [];
        $search = $request['search'];
        if ($request->has('search')) {
            $key = explode(' ', $request['search']);
            $customers = User::where(function ($q) use ($key) {
                foreach ($key as $value) {
                    $q->orWhere('f_name', 'like', "%{$value}%")
                        ->orWhere('l_name', 'like', "%{$value}%")
                        ->orWhere('email', 'like', "%{$value}%")
                        ->orWhere('phone', 'like', "%{$value}%");
                }
            });
            $query_param = ['search' => $request['search']];
        } else {
            $customers = new User();
        }

        $customers = $customers->latest()->customer()->paginate(Helpers::pagination_limit())->appends($query_param);
        return view('admin-views.customer.list', compact('customers', 'search'));
    }

    public function search(Request $request)
    {
        $key = explode(' ', $request['search']);
        $customers = User::where(function ($q) use ($key) {
            foreach ($key as $value) {
                $q->orWhere('f_name', 'like', "%{$value}%")
                    ->orWhere('l_name', 'like', "%{$value}%")
                    ->orWhere('email', 'like', "%{$value}%")
                    ->orWhere('phone', 'like', "%{$value}%");
            }
        })->get();
        return response()->json([
            'view' => view('admin-views.customer.partials._table', compact('customers'))->render(),
        ]);
    }

    public function view($id)
    {
        $user = User::with('emoney')->find($id);
        return view('admin-views.view.details', compact('user'));
    }

    public function transaction(Request $request, $id)
    {
        $query_param = [];
        $search = $request['search'];
        if ($request->has('search')) {
            $key = explode(' ', $request['search']);

            $users = User::where(function ($q) use ($key) {
                foreach ($key as $value) {
                    $q->orWhere('id', 'like', "%{$value}%")
                        ->orWhere('phone', 'like', "%{$value}%")
                        ->orWhere('f_name', 'like', "%{$value}%")
                        ->orWhere('l_name', 'like', "%{$value}%")
                        ->orWhere('email', 'like', "%{$value}%");
                }
            })->get()->pluck('id')->toArray();

            $transactions = Transaction::where(function ($q) use ($key, $users) {
                foreach ($key as $value) {
                    $q->orWhereIn('from_user_id', $users)
                        ->orWhere('to_user_id', $users)
                        ->orWhere('transaction_type', 'like', "%{$value}%")
                        ->orWhere('balance', 'like', "%{$value}%");
                }
            });
            $query_param = ['search' => $request['search']];
        } else {
            $transactions = new Transaction();
        }


        $transactions = $transactions->where('user_id', $id)->latest()->paginate(Helpers::pagination_limit())->appends($query_param);

        $user = User::find($id);
        return view('admin-views.view.transaction', compact('user', 'transactions', 'search'));
    }

    public function status(Request $request)
    {
        $user = User::find($request->id);
        $user->is_active = !$user->is_active;
        $user->save();
        Toastr::success('Customer status updated!');

        return back();
    }

    public function edit($id)
    {
        $customer = User::find($id);
        return view('admin-views.customer.edit', compact('customer'));
    }

    public function update(Request $request, $id)
    {
        $request->validate([
            'f_name' => 'required',
            'l_name' => 'required',
            //'image' => 'required',
            //'email' => 'unique:users',
            //'phone' => 'required|unique:users|min:5|max:20',
            //'gender' => 'required',
            'occupation' => 'required',
            //'password' => 'required|min:4|max:4',
        ]);

        $customer = User::find($id);

        if ($request->has('image')) {
            $image_name = Helpers::update('customer/', $customer->image ?? '', 'png', $request->file('logo'));
        } else {
            $image_name = $customer->image ?? '';
        }

        $customer->f_name = $request->f_name;
        $customer->l_name = $request->l_name;
        $customer->image = $image_name;
        $customer->email = $request->email ?? $customer->email;
        //$customer->phone = $customer->phone;
        $customer->gender = $request->has('gender') ? $request->gender : $customer->gender;
        $customer->occupation = $request->occupation;
        if ($request->has('password') && strlen($request->password) > 3) {
            $customer->password = bcrypt($request->password);
        }
        $customer->type = 2;    //['Admin'=>0, 'Agent'=>1, 'Customer'=>2]
        $customer->referral_id = $request->referral_id ?? null;
        $customer->save();

        Toastr::success('Agent updated successfully!');
        return redirect(route('admin.customer.list'));
    }
}
