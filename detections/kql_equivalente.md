# Equivalente aproximado en un SIEM (Microsoft Sentinel, KQL)

Boceto **no probado** para mostrar a un equipo de detección cómo se vería la misma idea sin Python:
una serie diaria por usuario, descomposición estacional y anomalías sobre el residuo.

Según la documentación de Microsoft, `series_decompose_anomalies(Series, Threshold, Seasonality, Trend, ...)`
llama a `series_decompose()` para obtener la línea base y el residuo, calcula un puntaje con
`series_outliers()` (por defecto, cercas de Tukey con rango de percentiles 10 a 90) y marca anomalías
con el umbral (1,5 por defecto). Devuelve la bandera (+1, -1, 0), el puntaje y la línea base.
No es SARIMA, pero comparte la lógica "observado frente a esperado".
Fuente: https://learn.microsoft.com/en-us/kusto/query/series-decompose-anomalies-function

```kusto
let inicio = ago(182d);                       // misma ventana que la reestimación mensual del repositorio
let fin = startofday(now());
SecurityEvent
| where TimeGenerated between (inicio .. fin)
| where EventID == 4624                       // inicio de sesión exitoso
| make-series Logons = count() default = 0
    on TimeGenerated from inicio to fin step 1d by TargetUserName
| extend (Anomalias, Puntaje, Esperado) =
    series_decompose_anomalies(Logons, 3.0, 7, "avg")      // umbral 3,0; periodo de 7 días
| mv-expand TimeGenerated to typeof(datetime), Logons to typeof(long),
            Anomalias to typeof(int), Puntaje to typeof(double), Esperado to typeof(double)
| where TimeGenerated == fin - 1d and Anomalias == 1        // solo el último día cerrado, solo aumentos
| project TimeGenerated, TargetUserName, Logons, Esperado, Puntaje
| top 10 by Puntaje desc                                     // presupuesto diario de alertas
```

Diferencias con este repositorio: aquí la línea base es un SARIMA(0,0,0)(1,0,1)7 por usuario y
señal elegido por AIC, se reestima una vez al mes con los últimos 182 días, se agrega contexto de
pares (SARIMAX), se combinan nueve señales con A = max z⁺ y se evalúa contra el answer key de CERT
con PR-AUC, incidentes detectados y falsas alertas por 1.000 usuario-día.
