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
