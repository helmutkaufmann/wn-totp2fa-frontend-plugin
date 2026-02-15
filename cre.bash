#!/bin/bash

# Create directories
mkdir -p classes/Middleware
mkdir -p controllers
mkdir -p models
mkdir -p views
mkdir -p lang/en
mkdir -p updates

# Create classes/TotpManager.php
cat > classes/TotpManager.php << 'EOF'
<?php namespace Mercator\Totp2faFrontend\Classes;

use PragmaRX\Google2FA\Google2FA;
use BaconQrCode\Renderer\ImageRenderer;
use BaconQrCode\Renderer\RendererStyle\RendererStyle;
use BaconQrCode\Writer;

class TotpManager
{
    protected $google2fa;

    public function __construct()
    {
        $this->google2fa = new Google2FA();
    }

    public function generateSecret()
    {
        return $this->google2fa->generateSecretKey();
    }

    public function generateQrCode($secret, $email, $issuer = 'Winter CMS')
    {
        $renderer = new ImageRenderer(new RendererStyle(400));
        $writer = new Writer($renderer);
        $url = $this->google2fa->getQRCodeUrl($issuer, $email, $secret);
        return base64_encode($writer->writeString($url));
    }

    public function verifyCode($secret, $code)
    {
        try {
            return $this->google2fa->verifyKey($secret, $code, 2);
        } catch (\Exception $e) {
            return false;
        }
    }

    public function verifyCodeWithWindow($secret, $code, $window = 1)
    {
        try {
            $timestamp = $this->google2fa->getTimestamp();
            for ($i = -$window; $i <= $window; $i++) {
                $expectedCode = $this->google2fa->totp($secret, $timestamp + ($i * 30));
                if ($code === $expectedCode) {
                    return true;
                }
            }
            return false;
        } catch (\Exception $e) {
            return false;
        }
    }

    public function getCurrentCounter()
    {
        return floor(microtime(true) / 30);
    }
}
EOF

# Create classes/RecoveryCodeGenerator.php
cat > classes/RecoveryCodeGenerator.php << 'EOF'
<?php namespace Mercator\Totp2faFrontend\Classes;

use Illuminate\Support\Str;

class RecoveryCodeGenerator
{
    const CODE_COUNT = 10;

    public static function generate($count = self::CODE_COUNT)
    {
        $codes = [];
        for ($i = 0; $i < $count; $i++) {
            $codes[] = self::generateSingleCode();
        }
        return $codes;
    }

    protected static function generateSingleCode()
    {
        $part1 = strtoupper(Str::random(4));
        $part2 = strtoupper(Str::random(4));
        return $part1 . '-' . $part2;
    }

    public static function format($code)
    {
        return strtoupper(str_replace(' ', '', $code));
    }

    public static function validate($code)
    {
        $formatted = self::format($code);
        return preg_match('/^[A-Z0-9]{4}-[A-Z0-9]{4}$/', $formatted) === 1;
    }

    public static function codeExists($code, $codes)
    {
        $formatted = self::format($code);
        foreach ($codes as $storedCode) {
            if (self::format($storedCode) === $formatted) {
                return true;
            }
        }
        return false;
    }

    public static function removeCode($code, $codes)
    {
        $formatted = self::format($code);
        $remaining = [];
        foreach ($codes as $storedCode) {
            if (self::format($storedCode) !== $formatted) {
                $remaining[] = $storedCode;
            }
        }
        return $remaining;
    }
}
EOF

# Create classes/Enforcement.php
cat > classes/Enforcement.php << 'EOF'
<?php namespace Mercator\Totp2faFrontend\Classes;

class Enforcement
{
    public static function is2faEnabled($user)
    {
        return $user && (bool) $user->twofa_enabled;
    }

    public static function isVerifiedForSession($user)
    {
        if (!self::is2faEnabled($user)) {
            return true;
        }
        $verifiedAt = session('mercator.totp2fa.verified_at');
        if (!$verifiedAt) {
            return false;
        }
        $expiry = $verifiedAt + (30 * 24 * 60 * 60);
        return time() < $expiry;
    }

    public static function markVerifiedForSession()
    {
        session(['mercator.totp2fa.verified_at' => time()]);
    }

    public static function clearSessionVerification()
    {
        session()->forget('mercator.totp2fa.verified_at');
    }

    public static function shouldShowRecoveryCodes()
    {
        return session()->has('mercator.totp2fa.show_recovery_codes');
    }

    public static function setShowRecoveryCodes()
    {
        session(['mercator.totp2fa.show_recovery_codes' => true]);
    }

    public static function clearShowRecoveryCodes()
    {
        session()->forget('mercator.totp2fa.show_recovery_codes');
    }

    public static function setIntendedUrl($url)
    {
        session(['mercator.totp2fa.intended' => $url]);
    }

    public static function getIntendedUrl($default = '/')
    {
        return session('mercator.totp2fa.intended', $default);
    }

    public static function clearIntendedUrl()
    {
        session()->forget('mercator.totp2fa.intended');
    }
}
EOF

# Create classes/CryptHelper.php
cat > classes/CryptHelper.php << 'EOF'
<?php namespace Mercator\Totp2faFrontend\Classes;

use Illuminate\Support\Facades\Crypt;

class CryptHelper
{
    public static function encrypt($data)
    {
        return Crypt::encryptString($data);
    }

    public static function decrypt($data)
    {
        try {
            return Crypt::decryptString($data);
        } catch (\Exception $e) {
            return null;
        }
    }

    public static function encryptRecoveryCodes($codes)
    {
        return self::encrypt(json_encode($codes));
    }

    public static function decryptRecoveryCodes($encrypted)
    {
        $json = self::decrypt($encrypted);
        if (!$json) {
            return [];
        }
        return json_decode($json, true) ?? [];
    }

    public static function encryptSecret($secret)
    {
        return self::encrypt($secret);
    }

    public static function decryptSecret($encrypted)
    {
        return self::decrypt($encrypted);
    }
}
EOF

# Create classes/Middleware/VerifyTotp2faForUser.php
cat > classes/Middleware/VerifyTotp2faForUser.php << 'EOF'
<?php namespace Mercator\Totp2faFrontend\Classes\Middleware;

use Closure;
use Mercator\Totp2faFrontend\Classes\Enforcement;

class VerifyTotp2faForUser
{
    public function handle($request, Closure $next)
    {
        $user = $request->user();
        if (!$user) {
            return $next($request);
        }
        if (!Enforcement::is2faEnabled($user)) {
            return $next($request);
        }
        if (Enforcement::isVerifiedForSession($user)) {
            return $next($request);
        }
        Enforcement::setIntendedUrl($request->url());
        return redirect()->route('totp2fa.challenge');
    }
}
EOF

# Create controllers/FrontendTotp2faController.php
cat > controllers/FrontendTotp2faController.php << 'EOF'
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
EOF

# Create controllers/LoginTotp2faController.php
cat > controllers/LoginTotp2faController.php << 'EOF'
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
EOF

# Create models/TotpSecret.php
cat > models/TotpSecret.php << 'EOF'
<?php namespace Mercator\Totp2faFrontend\Models;

use Winter\Storm\Database\Model;

class TotpSecret extends Model
{
    public $table = 'totp_secrets';
    public $timestamps = true;
    protected $fillable = ['user_id', 'secret', 'verified_at'];
    protected $dates = ['verified_at', 'created_at', 'updated_at'];
    
    public function user()
    {
        return $this->belongsTo('App\Models\User');
    }
}
EOF

# Create models/TotpRecoveryCode.php
cat > models/TotpRecoveryCode.php << 'EOF'
<?php namespace Mercator\Totp2faFrontend\Models;

use Winter\Storm\Database\Model;

class TotpRecoveryCode extends Model
{
    public $table = 'totp_recovery_codes';
    public $timestamps = true;
    protected $fillable = ['user_id', 'code', 'used_at'];
    protected $dates = ['used_at', 'created_at', 'updated_at'];
    
    public function user()
    {
        return $this->belongsTo('App\Models\User');
    }
    
    public function isUsed()
    {
        return $this->used_at !== null;
    }
    
    public function markAsUsed()
    {
        $this->used_at = now();
        $this->save();
    }
}
EOF

# Create views/setup.htm
cat > views/setup.htm << 'EOF'
<div class="container mt-5">
    <div class="row justify-content-center">
        <div class="col-md-6">
            <div class="card">
                <div class="card-header"><h4>Enable Two-Factor Authentication</h4></div>
                <div class="card-body">
                    @if ($errors->any())
                        <div class="alert alert-danger">
                            @foreach ($errors->all() as $error) <p>{{ $error }}</p> @endforeach
                        </div>
                    @endif
                    <p>Scan this QR code with your authenticator app</p>
                    <div class="text-center mb-4">
                        <h5>QR Code</h5>
                        <img src="data:image/png;base64,{{ $qrCode }}" alt="QR Code" style="max-width: 100%; height: auto;">
                    </div>
                    <div class="form-group mb-3">
                        <label>Or enter manually:</label>
                        <input type="text" class="form-control" value="{{ $secret }}" readonly>
                    </div>
                    <form method="POST" action="{{ route('totp2fa.store') }}">
                        @csrf
                        <input type="hidden" name="secret" value="{{ $secret }}">
                        <div class="form-group mb-3">
                            <label>Verification Code</label>
                            <input type="text" class="form-control" name="code" placeholder="000000" required autofocus>
                        </div>
                        <button type="submit" class="btn btn-primary btn-block">Enable 2FA</button>
                    </form>
                </div>
            </div>
        </div>
    </div>
</div>
EOF

# Create views/verify.htm
cat > views/verify.htm << 'EOF'
<div class="container mt-5">
    <div class="row justify-content-center">
        <div class="col-md-6">
            <div class="card">
                <div class="card-header"><h4>Verification Code</h4></div>
                <div class="card-body">
                    @if ($errors->any())
                        <div class="alert alert-danger">@foreach ($errors->all() as $error) <p>{{ $error }}</p> @endforeach</div>
                    @endif
                    <form method="POST">
                        @csrf
                        <div class="form-group mb-3">
                            <label>Code</label>
                            <input type="text" class="form-control" name="code" placeholder="000000" required autofocus>
                        </div>
                        <div class="form-check mb-3">
                            <input class="form-check-input" type="checkbox" name="is_recovery_code" id="rc">
                            <label class="form-check-label" for="rc">Use recovery code</label>
                        </div>
                        <button type="submit" class="btn btn-primary btn-block">Verify</button>
                    </form>
                </div>
            </div>
        </div>
    </div>
</div>
EOF

# Create views/recovery.htm
cat > views/recovery.htm << 'EOF'
<div class="container mt-5">
    <div class="row justify-content-center">
        <div class="col-md-6">
            <div class="card">
                <div class="card-header"><h4>Recovery Codes</h4></div>
                <div class="card-body">
                    <div class="alert alert-warning"><strong>Important!</strong> Save these codes now.</div>
                    <div class="bg-light p-3 rounded mb-3" id="codesContainer">
                        <code style="white-space: pre-wrap;">@foreach ($codes as $code) {{ $code }} @endforeach</code>
                    </div>
                    <div class="mb-3">
                        <button class="btn btn-secondary btn-sm" onclick="copyToClipboard()">Copy</button>
                        <button class="btn btn-secondary btn-sm" onclick="downloadCodes()">Download</button>
                    </div>
                    <form method="POST" action="{{ route('totp2fa.recovery.acknowledge') }}">
                        @csrf
                        <button type="submit" class="btn btn-primary btn-block">I saved codes</button>
                    </form>
                </div>
            </div>
        </div>
    </div>
</div>
<script>
function copyToClipboard() { navigator.clipboard.writeText(document.querySelector('#codesContainer code').innerText); alert('Copied!'); }
function downloadCodes() { var t = document.querySelector('#codesContainer code').innerText; var e = document.createElement('a'); e.setAttribute('href', 'data:text/plain;charset=utf-8,' + encodeURIComponent(t)); e.setAttribute*

