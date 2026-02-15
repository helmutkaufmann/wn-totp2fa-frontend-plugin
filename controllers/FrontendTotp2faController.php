<?php namespace Mercator\Totp2faFrontend\Controllers;

use Auth;
use Illuminate\Routing\Controller;
use Mercator\Totp2faFrontend\Classes\TotpManager;
use Mercator\Totp2faFrontend\Classes\RecoveryCodeGenerator;
use Mercator\Totp2faFrontend\Classes\Enforcement;
use Mercator\Totp2faFrontend\Classes\CryptHelper;

class FrontendTotp2faController extends Controller
{
    public function setup()
    {
        $user = Auth::user();
        if (!$user) return redirect('/login');
        $manager = new TotpManager();
        $secret = $manager->generateSecret();
        $qrCode = $manager->generateQrCode($secret, $user->email);
        return view('mercator.totp2fafrontend::setup', [
            'secret' => $secret,
            'qrCode' => $qrCode,
            'email' => $user->email
        ]);
    }

    public function storeSetup()
    {
        $user = Auth::user();
        if (!$user) return redirect('/login');
        $code = request('code');
        $secret = request('secret');
        $manager = new TotpManager();
        if (!$manager->verifyCodeWithWindow($secret, $code)) {
            return back()->with('error', 'Invalid code. Please try again.');
        }
        $user->twofa_enabled = true;
        $user->twofa_secret = CryptHelper::encryptSecret($secret);
        $codes = RecoveryCodeGenerator::generate();
        $user->twofa_recovery_codes = CryptHelper::encryptRecoveryCodes($codes);
        $user->save();
        Enforcement::setShowRecoveryCodes();
        return redirect()->route('totp2fa.recovery');
    }

    public function recovery()
    {
        $user = Auth::user();
        if (!$user) return redirect('/login');
        if (!Enforcement::shouldShowRecoveryCodes()) {
            return redirect()->route('totp2fa.manage')->with('error', 'Recovery codes have already been shown.');
        }
        $codes = CryptHelper::decryptRecoveryCodes($user->twofa_recovery_codes);
        return view('mercator.totp2fafrontend::recovery', ['codes' => $codes]);
    }

    public function acknowledgeRecovery()
    {
        Enforcement::clearShowRecoveryCodes();
        return redirect()->route('totp2fa.manage')->with('success', 'Recovery codes acknowledged.');
    }

    public function manage()
    {
        $user = Auth::user();
        if (!$user) return redirect('/login');
        $codes = CryptHelper::decryptRecoveryCodes($user->twofa_recovery_codes);
        $codeCount = count($codes);
        return view('mercator.totp2fafrontend::manage', [
            'codeCount' => $codeCount,
            'twofa_enabled' => $user->twofa_enabled
        ]);
    }

    public function regenerate()
    {
        $user = Auth::user();
        if (!$user) return redirect('/login');
        $codes = RecoveryCodeGenerator::generate();
        $user->twofa_recovery_codes = CryptHelper::encryptRecoveryCodes($codes);
        $user->save();
        Enforcement::setShowRecoveryCodes();
        return redirect()->route('totp2fa.recovery');
    }

    public function disable()
    {
        $user = Auth::user();
        if (!$user) return redirect('/login');
        $user->twofa_enabled = false;
        $user->twofa_secret = null;
        $user->twofa_recovery_codes = null;
        $user->save();
        return redirect()->route('totp2fa.manage')->with('success', '2FA has been disabled.');
    }
}
