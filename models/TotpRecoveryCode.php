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
