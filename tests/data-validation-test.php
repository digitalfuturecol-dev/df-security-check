<?php
/**
 * Pruebas de validación de datos. Uso, en un sitio de pruebas con el plugin activo:
 *     wp eval-file tests/data-validation-test.php
 *
 * @package DF_Security_Check
 */

// phpcs:disable
$base = json_decode(file_get_contents(DFSC_DIR.'data/advisories.json'), true);
function chk($name,$cond){ echo ($cond?"PASS":"FAIL")."  $name\n"; }
chk('incluido válido', is_array(DFSC_Advisories::validate($base)) && count(DFSC_Advisories::validate($base)['advisories'])>=1);
$x=$base; $x['schema']=2; chk('schema desconocido rechazado', null===DFSC_Advisories::validate($x));
$x=$base; $x['updated']='2026-10-21<script>'; chk('fecha inválida rechazada', null===DFSC_Advisories::validate($x));
$x=$base; $x['advisories'][0]['fixed']['8.4']='8.4.27; rm -rf'; $v=DFSC_Advisories::validate($x); chk('versión inyectada: aviso descartado', count($v['advisories'])===1);
$x=$base; $x['advisories'][0]['fixed']['8.4']='8.3.99'; $v=DFSC_Advisories::validate($x); chk('versión de otra rama: aviso descartado', count($v['advisories'])===1);
$x=$base; $x['advisories'][0]['cves'][]='CVE-XSS"><img>'; $v=DFSC_Advisories::validate($x); chk('CVE inválido: aviso descartado', count($v['advisories'])===1);
$x=$base; $x['advisories'][0]['title']['es']='<img src=x onerror=alert(1)>Hola'; $v=DFSC_Advisories::validate($x); chk('HTML en título eliminado', $v['advisories'][0]['title']['es']==='Hola');
$x=$base; $x['advisories'][0]['url']='javascript:alert(1)'; $v=DFSC_Advisories::validate($x); chk('URL javascript: eliminada', $v['advisories'][0]['url']==='');
$x=$base; $x['advisories'][0]['severity']='none'; $v=DFSC_Advisories::validate($x); chk('severidad inválida: aviso descartado', count($v['advisories'])===1);
chk('basura rechazada', null===DFSC_Advisories::validate('hola') && null===DFSC_Advisories::validate(null));

// Remoto simulado
function mock($body){ remove_all_filters('pre_http_request'); add_filter('pre_http_request', function($p,$a,$u) use ($body){ if (strpos($u,'raw.githubusercontent.com')===false) return $p; return ['headers'=>[],'body'=>$body,'response'=>['code'=>200,'message'=>'OK'],'cookies'=>[],'filename'=>null]; },10,3); delete_site_transient(DFSC_Advisories::DATA_CACHE_KEY); }
$r=new ReflectionProperty('DFSC_Advisories','data'); $r->setAccessible(true);
$new=$base; $new['updated']='2026-11-05'; $new['advisories'][]=['id'=>'php-2026-11','cves'=>['CVE-2026-120001'],'severity'=>'critical','date'=>'2026-11-05','min_affected'=>'8.1.0','fixed'=>['8.3'=>'8.3.37','8.4'=>'8.4.28'],'title'=>['en'=>'Test November advisory','es'=>'Aviso de prueba de noviembre'],'summary'=>['en'=>'x','es'=>'y']];
mock(json_encode($new)); $r->setValue(null,null); $i=DFSC_Advisories::data_info(); chk('remoto más nuevo se usa', $i['source']==='remote' && $i['updated']==='2026-11-05' && count(DFSC_Advisories::list_advisories())===count($base['advisories'])+1);
$ev=DFSC_Advisories::evaluate('8.3.36'); chk('aviso nuevo afecta 8.3.36', end($ev)['status']==='vulnerable' && end($ev)['fixed_in']==='8.3.37');
$old=$base; $old['updated']='2026-01-01'; mock(json_encode($old)); $r->setValue(null,null); chk('remoto más viejo se ignora', DFSC_Advisories::data_info()['source']==='bundled');
mock('{"schema":1, broken'); $r->setValue(null,null); chk('remoto roto se ignora', DFSC_Advisories::data_info()['source']==='bundled');
add_filter('dfsc_data_url','__return_empty_string'); mock(json_encode($new)); $r->setValue(null,null); chk('consulta remota desactivable', DFSC_Advisories::data_info()['source']==='bundled');
remove_all_filters('dfsc_data_url'); remove_all_filters('pre_http_request'); delete_site_transient(DFSC_Advisories::DATA_CACHE_KEY);
