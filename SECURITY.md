# Política de seguridad / Security policy

## Reportar una vulnerabilidad

Si encuentras una vulnerabilidad en DF Security Check, **no abras un issue público**.

Repórtala de forma privada desde la pestaña **Security → Report a vulnerability** de este repositorio (GitHub Private Vulnerability Reporting), o escribe a **develop@digitalfuture.com.co** con el asunto `[SECURITY] DF Security Check`.

Incluye la versión del plugin, los pasos para reproducirla y el impacto que observaste.

- Confirmamos la recepción en un plazo de **3 días hábiles**.
- Publicamos la corrección y el aviso de seguridad en cuanto la solución esté lista, y damos crédito a quien la reportó, si así lo desea.

## Versiones con soporte

Solo la última versión publicada recibe correcciones de seguridad.

## Datos de vulnerabilidades

El plugin descarga `data/advisories.json` desde la rama `main` de este repositorio. Por eso:

- La rama `main` está protegida: los cambios entran solo por pull request revisado.
- El plugin valida cada campo del archivo descargado (formato de fechas, versiones, CVE y URL) y trata los textos como texto plano. Un archivo inválido se descarta y se usan los datos incluidos en el plugin.
- Si crees que el archivo publicado contiene un dato incorrecto, repórtalo como se indica arriba.

---

## Reporting a vulnerability

Please **do not open a public issue**. Report it privately through **Security → Report a vulnerability** in this repository, or email **develop@digitalfuture.com.co** with the subject `[SECURITY] DF Security Check`. We acknowledge reports within 3 business days and credit reporters who wish to be named. Only the latest release receives security fixes.
