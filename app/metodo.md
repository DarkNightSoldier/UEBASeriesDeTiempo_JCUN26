## Glosario

| Término | Qué significa en este trabajo |
|---|---|
| Amenaza interna | Daño que causa alguien con acceso legítimo a la organización, como un empleado que roba información o sabotea sistemas. |
| UEBA | Análisis del comportamiento de usuarios y entidades: aprende cómo se comporta normalmente cada usuario y avisa cuando se aparta de ese patrón. |
| Serie de tiempo | Un dato medido día tras día, por ejemplo cuántas memorias USB conecta un usuario cada día. Lo de hoy suele parecerse a lo de días anteriores y depende del día de la semana. |
| Ciclo semanal | El ritmo que se repite cada 7 días: mucha actividad entre semana, casi nada el fin de semana. |
| Regla global | El mismo umbral para todos los usuarios de la organización, como muchas reglas de los sistemas de alertas. |
| Línea base estática | El promedio y la variación de la historia de cada usuario, recalculados cada mes. Usa el mismo límite un lunes que un domingo. |
| Regla ingenua | Espera hoy lo mismo que pasó el mismo día de la semana anterior. Tiene en cuenta el ciclo semanal, pero sin un modelo. |
| ARIMA | Modelo estadístico de pronóstico que estima el valor de hoy con lo ocurrido en los días inmediatamente anteriores. Aprende, por ejemplo, que tras un día muy activo suele venir otro parecido. No distingue el día de la semana. |
| SARIMA | Versión estacional de ARIMA. Aquí pronostica cada día con el promedio del mismo día de la semana en semanas anteriores; por eso espera más actividad un lunes que un domingo. |
| SARIMAX + pares | SARIMA que además tiene en cuenta cuánta actividad hubo ese día en el departamento del usuario. Si todo el departamento trabaja más un día, no alerta solo por eso. |
| Box-Jenkins | La receta estadística para construir estos modelos: identificar el patrón de la serie, estimar el modelo, comprobar que no quede patrón sin explicar y pronosticar. |
| Límite del 99 % | El valor que, según la historia de ese usuario, un día normal no debería superar más de 1 vez de cada 100 en ese contador. Superarlo es inusual. |
| Alerta | Aviso de que un usuario se alejó de lo normal. Es una señal para investigar, no un ataque confirmado. |
| Falsa alarma | Alerta sobre un día que no era malicioso. |
| Cola de revisión | Los usuarios más anómalos de cada día, en el orden en que el analista los revisa. |
| Día malicioso | Un día en que el usuario hizo parte de un incidente, según el registro de incidentes del conjunto de datos. |
| PR-AUC | Nota de 0 a 1 que mide qué tan arriba quedan los días maliciosos al ordenar todos los días de la prueba juntos, del más al menos sospechoso. 1 es perfecto; elegir al azar da 0,0032. |
| Intervalo de confianza del 95 % | Se obtiene repitiendo el cálculo 1.000 veces con usuarios elegidos al azar (remuestreo bootstrap) y tomando el rango donde cae el 95 % de los resultados. Si no incluye el cero, la diferencia no depende de qué usuarios hay en los datos. |
| Prueba de Ljung-Box | Revisa si en los errores del pronóstico queda un patrón. Si todos los modelos fueran adecuados, cerca del 95 % de los ajustes no mostraría patrón; no encontrarlo no prueba que el modelo sea perfecto, pero encontrarlo indica que le faltó capturar parte del ritmo. |
| Usuario-día | Un usuario en un día concreto; es la unidad que se evalúa (309.661 en el periodo de prueba). |
| Puntaje | Cuántas desviaciones estándar se alejó lo observado de lo esperado en el contador más alterado del usuario ese día; con él se ordena la cola de revisión. |
| Reentrenamiento mensual | Cada mes los modelos se vuelven a estimar con los últimos 182 días. |
| Sin reentrenar (origen fijo) | Los modelos se estiman una sola vez, con los días anteriores al 10 de junio de 2010. |
| FAC | Función de autocorrelación: cuánto se parece la actividad de un día a la de k días antes. |
| FACP | Autocorrelación parcial: lo mismo que la FAC, pero descontando los días intermedios. |
| Periodograma | Separa la serie en ritmos; un pico en 7 días indica un ciclo semanal. |
| ADF y KPSS | Pruebas que dicen si el nivel de la serie es estable o se desplaza con el tiempo. |
| AIC | Criterio para elegir entre modelos: premia el buen ajuste y castiga la complejidad. |
| MAE y RMSE | Error promedio del pronóstico; el RMSE castiga más los errores grandes. |
| EDR | Protección de equipos que vigila acciones sospechosas en cada computador. |

## El problema

Las firmas detectan bien las amenazas conocidas, pero en gran medida no las desconocidas (NIST SP 800-94). En la amenaza interna y en el abuso de cuentas válidas (MITRE ATT&CK T1078) cada acción es legítima: lo anómalo es el patrón. Para buscarlo, los centros de operaciones de seguridad (SOC) usan reglas de umbral y líneas base de comportamiento, pero un umbral fijo trata igual un lunes que un domingo y genera ruido. Un analista de SOC lo resume así: «Sabemos que el 99 % de las alarmas que generamos son falsos positivos, pero aun así tenemos que revisarlas» (Alahmadi et al., 2022; traducción propia). Revisar tantas alarmas lleva al desgaste y a la desensibilización, y con más alertas de las que se pueden investigar se pierden ataques reales (Hassan et al., 2019). Y el problema es costoso: atender incidentes internos (descuidos de empleados, empleados maliciosos y robo de credenciales) le cuesta a cada organización USD 19,5 millones al año en promedio, según un estudio de 354 organizaciones (Ponemon Institute, 2026).

La actividad de un usuario, como el tráfico de red (Brutlag, 2000; Rajchel et al., 2020), es una serie de tiempo con ciclos diarios y semanales. Por eso la línea base debería ser un modelo de series de tiempo.

## Pregunta

Con el mismo número de alertas diarias, es decir, con la misma carga de trabajo para el analista, ¿un modelo de series de tiempo por usuario detecta más actividad maliciosa que una regla global y que una línea base estática?

## Datos

CERT Insider Threat Test Dataset, versión r4.2 (Lindauer, 2020; Glasser y Lindauer, 2013). Es un conjunto sintético de 1.000 usuarios de una organización ficticia, con registros de inicios de sesión, memorias USB, archivos copiados a USB, correo, navegación web y directorio, del 2 de enero de 2010 al 16 de mayo de 2011 (500 días). Su registro de incidentes describe 70 casos de tres escenarios:

| Escenario | Casos | Qué hace el empleado malicioso |
|---|---|---|
| 1 | 30 | Empieza a entrar fuera de horario, usa memorias USB por primera vez y sube datos a wikileaks.org |
| 2 | 30 | Busca empleo en la competencia y copia datos a memorias USB mucho más que antes de renunciar |
| 3 | 10 | Un administrador instala un programa espía en el equipo de su supervisor y envía un correo masivo con la cuenta del supervisor |

Un usuario-día es malicioso si el registro de incidentes tiene un evento de ese usuario ese día; en el escenario 3 esto incluye la cuenta del supervisor, desde la que sale el correo masivo.

## Cómo funciona (cada noche)

1. **Contar.** Los registros se resumen en nueve contadores por usuario y día: inicios de sesión, inicios de sesión fuera de horario, equipos distintos usados, memorias USB conectadas, memorias USB conectadas fuera de horario, archivos copiados a USB, correos enviados, correos a destinatarios externos y páginas web visitadas. La jornada de 07:00 a 19:00 salió de los datos de entrenamiento: el 5 % de los días el primer inicio de sesión es antes de las 07:02, y la mediana del último cierre de sesión es 17:44. Fines de semana y festivos (días hábiles con menos de la mitad de los inicios de sesión habituales) cuentan como fuera de horario. Los modelos trabajan con log(1 + conteo).
2. **Pronosticar.** Para cada usuario y contador, un modelo SARIMA predice el valor esperado del día y su límite del 99 %.
3. **Comparar.** Para cada contador se mide cuántas desviaciones estándar se aleja lo observado de lo esperado (z). Solo cuentan los aumentos, y el puntaje del usuario es el mayor de sus nueve excesos (A = máximo de z⁺).
4. **Priorizar.** El analista revisa los k usuarios con mayor puntaje del día.

## Identificación Box-Jenkins

En la ventana de entrenamiento se analizaron las 9.000 series (1.000 usuarios por 9 contadores) con la función de autocorrelación (FAC), la autocorrelación parcial (FACP), el periodograma y las pruebas de estacionariedad ADF, aplicada a la serie sin el patrón semanal (Dickey y Fuller, 1979), y KPSS (Kwiatkowski et al., 1992). De las 5.700 series con al menos 5 % de días con actividad, el 94 % tiene ciclo semanal y en el 96 % ADF (sin el promedio de cada día de la semana) y KPSS son compatibles con un nivel estable, así que no hace falta diferenciarlas. ADF se aplica a la serie sin el patrón semanal porque ese patrón, que se repite siempre igual, le quita potencia a la prueba; sobre la serie original rechaza la raíz unitaria solo en el 35,5 %. Con 5.700 pruebas no se corrigió por comparaciones múltiples: los porcentajes son descriptivos. Los órdenes se eligieron por la menor mediana de diferencia de AIC en una muestra aleatoria de 60 usuarios: SARIMA(0,0,0)(1,0,1) con periodo 7 en ocho de los nueve contadores (en archivos copiados a USB, con un término MA(1)). Los coeficientes estimados (mediana de Φ = 0,997 y de Θ = -1,00) hacen que SARIMA aprenda, en la práctica, un perfil por día de la semana que se actualiza lentamente. Los residuos se validan con la prueba de Ljung-Box (rezago 14; Ljung y Box, 1978).

Las series con menos de 5 % de días con actividad (por ejemplo, memorias USB en quien nunca las usa) no se modelan con ARIMA: usan la línea base estática con una desviación mínima de 0,25, que funciona como detector de primera vez.

## Detectores comparados

| Detector | Equivale en un SOC a | Qué aporta |
|---|---|---|
| Regla global | «conteo mayor que K» para toda la organización | punto de partida |
| Línea base estática | media y desviación de la historia del usuario | personalizar por usuario |
| Regla ingenua | «hoy como el mismo día de la semana pasada» | ciclo semanal sin modelo |
| ARIMA | pronóstico con los días recientes | dependencia de un día al siguiente |
| SARIMA | pronóstico con el mismo día de semanas anteriores | ciclo semanal modelado |
| SARIMAX + pares | SARIMA con la mediana diaria de su departamento, sin el propio usuario | contexto de la organización |

## Evaluación

La partición es cronológica. Ningún incidente empieza antes del 10 de junio de 2010, así que el entrenamiento inicial (2 de enero a 9 de junio de 2010) no contiene ataques y los 70 incidentes quedan en la prueba (10 de junio de 2010 a 16 de mayo de 2011).

* **Reentrenamiento mensual (principal).** Al inicio de cada mes se reestiman los parámetros con los últimos 182 días (origen rodante; Tashman, 2000), como un perfil que se regenera periódicamente (NIST SP 800-94, sección 2.3.2). No usa el registro de incidentes: si hubo actividad maliciosa en la ventana, entra a la línea base, como pasaría en un SOC real.
* **Sin reentrenar (origen fijo, prueba de sensibilidad).** Los parámetros se estiman una sola vez con el entrenamiento inicial, como en BRITD (Song et al., 2024); el filtro de Kalman actualiza el pronóstico día a día.

NIST describe el dilema: un perfil estático «con el tiempo se vuelve impreciso», mientras que uno dinámico es «susceptible a intentos de evasión» si el atacante aumenta su actividad poco a poco (traducción propia). Comparar ambos protocolos mide ese intercambio.

La comparación principal usa el mismo número de alertas diarias, de 1 a 30: cuántos días maliciosos e incidentes encuentra cada detector. También se reporta el PR-AUC, adecuado cuando los casos positivos son muy pocos (Saito y Rehmsmeier, 2015), la proporción de días maliciosos detectados, las falsas alarmas por cada 1.000 usuario-día y la demora hasta la primera alerta. Los intervalos de confianza vienen de un remuestreo bootstrap por usuarios (1.000 repeticiones). Solo se evalúan los usuario-día activos, es decir, hasta el último inicio de sesión de cada usuario.

## Resultados principales

* **47 % más con el mismo trabajo.** Revisando 10 alertas al día, SARIMA encuentra 240 días de actividad maliciosa; la línea base estática, 163, y la regla global, 36. No depende de unos pocos usuarios: al remuestrearlos 1.000 veces, la ventaja de SARIMA quedó entre 43 y 117 días en el 95 % de los casos.
* **Siempre por encima.** Los tres modelos de series de tiempo encuentran más días maliciosos que la línea base estática con cualquier número de alertas diarias entre 1 y 30.
* **Más aciertos por alerta.** Para dar con un día malicioso, el analista revisa 14 alertas con SARIMA, 21 con la línea base estática y 95 con la regla global.
* **La línea base estática exige casi el doble.** Necesita 18 alertas diarias para encontrar lo que SARIMA encuentra con 10.
* **Un umbral fijo satura.** Si cada detector usa su propio límite del 99 %, sin tope diario, la regla global dispara 108 alertas al día (98 de cada 100 falsas) y SARIMA, 18,5 (95 de cada 100). La regla encuentra así más días maliciosos (594 frente a 304), pero con casi seis veces más alertas: por eso se compara con la misma carga.
* **El ritmo semanal da estabilidad.** Sin reentrenar, SARIMA mantiene 233 días maliciosos con 10 alertas diarias y ARIMA, que ignora el día de la semana, cae a 123 (la línea base estática, 171).
* **Lo que no favorece al modelo, también se reporta.** Sin reentrenar (origen fijo), SARIMA sigue encontrando más días maliciosos que la línea base estática en los 30 casos, pero en incidentes, con 6 a 11 alertas diarias, la línea base estática detecta más.

## Robustez

* **Convergencia de SARIMAX.** Con el límite de 60 iteraciones (30 en los reajustes que parten de la estimación anterior), statsmodels marcó como convergidos el 96 % de los ajustes SARIMA y cerca del 60 % de los SARIMAX. Al reestimar SARIMAX con hasta 300 y 150 iteraciones en 40 usuarios al azar (66.598 usuario-día-contador con reentrenamiento mensual), el percentil 99 del cambio en z fue 0,05 y cambió el 0,012 % de las decisiones de alerta del límite del 99 %. Ver `scripts/sensibilidad_convergencia.py`.
* **Validación Box-Jenkins.** La prueba de Ljung-Box no encuentra patrón en los errores del 82 % de los ajustes SARIMA con reentrenamiento mensual (si todos fueran adecuados se esperaría cerca del 95 %) y solo del 9 % de los ARIMA: sin el término semanal, el ciclo queda en los errores.
* **Calibración del límite.** En los días normales de la prueba, lo observado superó el límite del 99 % de SARIMA entre el 0,17 % y el 0,79 % de las veces según el contador (el valor nominal es 1 %): el límite es conservador. Como el puntaje toma el peor de nueve contadores, el 1,9 % de los usuario-día normales supera algún límite.
* **ARIMA.** Con reentrenamiento mensual su PR-AUC puntual (0,0346) es el más alto, pero la diferencia con SARIMA no es significativa (intervalo de confianza del 95 %: de -0,0029 a 0,0075) y sin reentrenar cae a 0,0204.

## Limitaciones

CERT es sintético: los resultados indican viabilidad, no desempeño en una organización real. Una anomalía es una desviación improbable que merece investigación, no un ataque confirmado. El conteo diario no ve una acción única sin cambio de volumen, ni lo que ya es costumbre para un usuario (por ejemplo, un robo con memorias USB fuera de horario en alguien que ya las conectaba así casi todos los días; la regla global sí lo detecta); eso sigue siendo tarea de la regla global, la protección de equipos (EDR) y las firmas. La línea base se reentrena sin usar etiquetas, así que un ataque largo puede entrar en ella.

## Fuentes

* Scarfone, K., Mell, P. (2007). *Guide to Intrusion Detection and Prevention Systems (IDPS)*. NIST SP 800-94. [csrc.nist.gov](https://csrc.nist.gov/pubs/sp/800/94/final)
* Alahmadi, B. A., Axon, L., Martinovic, I. (2022). 99% False Positives: A Qualitative Study of SOC Analysts' Perspectives on Security Alarms. *31st USENIX Security Symposium*, 2783-2800. [usenix.org](https://www.usenix.org/conference/usenixsecurity22/presentation/alahmadi)
* Hassan, W. U., Guo, S., Li, D., Chen, Z., Jee, K., Li, Z., Bates, A. (2019). NoDoze: Combatting Threat Alert Fatigue with Automated Provenance Triage. *NDSS*. [doi:10.14722/ndss.2019.23349](https://doi.org/10.14722/ndss.2019.23349)
* Brutlag, J. D. (2000). Aberrant Behavior Detection in Time Series for Network Monitoring. *USENIX LISA 2000*, 139-146. [usenix.org](https://www.usenix.org/conference/lisa-2000/aberrant-behavior-detection-time-series-network-service-monitoring)
* Lindauer, B. (2020). *Insider Threat Test Dataset*. Carnegie Mellon University. [doi:10.1184/R1/12841247.v1](https://doi.org/10.1184/R1/12841247.v1)
* Glasser, J., Lindauer, B. (2013). Bridging the Gap: A Pragmatic Approach to Generating Insider Threat Data. *IEEE Security and Privacy Workshops*, 98-104. [doi:10.1109/SPW.2013.37](https://doi.org/10.1109/SPW.2013.37)
* Song, S., Gao, N., Zhang, Y., Ma, C. (2024). BRITD: behavior rhythm insider threat detection with time awareness and user adaptation. *Cybersecurity*, 7, 2. [doi:10.1186/s42400-023-00190-9](https://doi.org/10.1186/s42400-023-00190-9)
* Zhang, C., Yang, G., Tian, T., Jiang, B., Lu, Z., Guo, T. (2026). BTITD: an insider threat detection method based on behavior-timestamp dual-stream network. *Cybersecurity*, 9, 179. [doi:10.1186/s42400-026-00591-6](https://doi.org/10.1186/s42400-026-00591-6)
* Rajchel, B., Monaco, J. V., Singh, G., Hu, A., Shingleton, J., Anderson, T. (2020). Temporal Behavior in Network Traffic as a Basis for Insider Threat Detection. *IEEE SSCI*, 1427-1434. [doi:10.1109/SSCI47803.2020.9308236](https://doi.org/10.1109/SSCI47803.2020.9308236)
* Tashman, L. J. (2000). Out-of-sample tests of forecasting accuracy: an analysis and review. *International Journal of Forecasting*, 16(4), 437-450. [doi:10.1016/S0169-2070(00)00065-0](https://doi.org/10.1016/S0169-2070(00)00065-0)
* Saito, T., Rehmsmeier, M. (2015). The Precision-Recall Plot Is More Informative than the ROC Plot When Evaluating Binary Classifiers on Imbalanced Datasets. *PLOS ONE*, 10(3), e0118432. [doi:10.1371/journal.pone.0118432](https://doi.org/10.1371/journal.pone.0118432)
* Ljung, G. M., Box, G. E. P. (1978). On a measure of lack of fit in time series models. *Biometrika*, 65(2), 297-303. [doi:10.1093/biomet/65.2.297](https://doi.org/10.1093/biomet/65.2.297)
* Dickey, D. A., Fuller, W. A. (1979). Distribution of the Estimators for Autoregressive Time Series with a Unit Root. *JASA*, 74(366a), 427-431. [doi:10.1080/01621459.1979.10482531](https://doi.org/10.1080/01621459.1979.10482531)
* Kwiatkowski, D., Phillips, P. C. B., Schmidt, P., Shin, Y. (1992). Testing the null hypothesis of stationarity against the alternative of a unit root. *Journal of Econometrics*, 54(1-3), 159-178. [doi:10.1016/0304-4076(92)90104-Y](https://doi.org/10.1016/0304-4076(92)90104-Y)
* Seabold, S., Perktold, J. (2010). Statsmodels: Econometric and Statistical Modeling with Python. *9th Python in Science Conference*, 92-96. [doi:10.25080/Majora-92bf1922-011](https://doi.org/10.25080/Majora-92bf1922-011)
* Microsoft (2025). Advanced threat detection with User and Entity Behavior Analytics (UEBA) in Microsoft Sentinel. [learn.microsoft.com](https://learn.microsoft.com/en-us/azure/sentinel/identify-threats-with-entity-behavior-analytics)
* MITRE ATT&CK. T1078 Valid Accounts y T1052.001 Exfiltration over USB. [attack.mitre.org](https://attack.mitre.org/techniques/T1078/)
* Ponemon Institute (2026). *2026 Cost of Insider Risks: Global Report* (patrocinado por DTEX). [ponemonsullivanreport.com](https://ponemonsullivanreport.com/2026/05/2026-cost-of-insider-risks-global/)

## Datos

CERT Insider Threat Test Dataset (Lindauer, 2020), Carnegie Mellon University, licencia CC BY 4.0. Disponible en [kilthub.cmu.edu](https://kilthub.cmu.edu/articles/dataset/Insider_Threat_Test_Dataset/12841247) ([doi:10.1184/R1/12841247](https://doi.org/10.1184/R1/12841247)).
