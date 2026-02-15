<?php namespace Mercator\Totp2faFrontend\Controllers;

use Auth;
use Illuminate\Routing\Controller;
use Mercator\Totp2faFrontend\Classes\TotpManager;
use Mercator\Totp2faFrontend\Classes\RecoveryCodeGenerator;
use Mercator\Totp2faFrontend\Classes\Enforcement;
use Mercator\Totp2faFrontend\Classes\CryptHelper;

class LoginTotp2faController extends Controller
{
    public function challenge()
    {
        if (!session('totp2fa_user_id')) {
            return redirect('/login');
        }
        return view('mercator.totp2fafrontend::login-challenge');
    }

    public function verify()
    {
        $userId = session('totp2fa_user_id');
        if (!$userId) return redirect('/login');
        $user = \App\Models\User::find($userId);
        if (!$user) return redirect('/login');
        $code = request('code');
        $isRecoveryCode = request('is_recovery_code') === 'true';
        if ($isRecoveryCode) {
            if ($this->verifyRecoveryCode($user, $code)) {
                Auth::login($user);
                session()->forget('totp2fa_user_id');
                Enforcement::markVerifiedForSession();
                return redirect('/')->with('success', 'Logged in successfully');
            }
        } else {
            $secret = CryptHelper::decryptSecret($user->twofa_secret);
            $manager = new TotpManager();
            if ($manager->verifyCodeWithWindow($secret, $code)) {
                Auth::login($user);
                session()->forget('totp2fa_user_id');
                Enforcement::markVerifiedForSession();
                return redirect('/')->with('success', 'Logged in successfully');
            }
        }
        return back()->with('error', 'Invalid code. Please try again.');
    }

    protected function verifyRecoveryCode($user, $code)
    {
        $codes = CryptHelper::decryptRecoveryCodes($user->twofa_recovery_codes);
        if (!RecoveryCodeGenerator::codeExists($code, $codes)) {
            return false;
        }
        $remaining = RecoveryCodeGenerator::removeCode($code, $codes);
        $user->twofa_recovery_codes = CryptHelper::encryptRecoveryCodes($remaining);
        $user->save();
        return true;
    }
}
