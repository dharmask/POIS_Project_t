import React, { useEffect, useState } from "react";
import { api } from "./api";
import {
  Badge,
  Field,
  PanelCard,
  ResultArea,
  SegControl,
  Spinner,
  useAsync,
} from "./shared";

function formatNumber(value, digits = 2) {
  if (typeof value !== "number" || Number.isNaN(value)) {
    return "0";
  }
  if (Math.abs(value) >= 1000) {
    return value.toLocaleString(undefined, { maximumFractionDigits: digits });
  }
  return value.toFixed(digits);
}

function pickCurve(curves, nBits) {
  return curves?.find((curve) => curve.n_bits === nBits) ?? curves?.[0] ?? null;
}

function buildPath(points, xMax, width, height, padding) {
  if (!points?.length || xMax <= 0) {
    return "";
  }

  return points
    .map((point, index) => {
      const x = padding.left + ((point.queries || 0) / xMax) * (width - padding.left - padding.right);
      const y = height - padding.bottom - ((point.probability || 0) * (height - padding.top - padding.bottom));
      return `${index === 0 ? "M" : "L"}${x.toFixed(2)} ${y.toFixed(2)}`;
    })
    .join(" ");
}

function ProbabilityChart({
  theoretical = [],
  empirical = [],
  nBits,
  currentQuery = null,
  collisionQuery = null,
  expectedQuery = null,
}) {
  const width = 620;
  const height = 250;
  const padding = { top: 20, right: 18, bottom: 36, left: 46 };
  const xMax = Math.max(
    1,
    ...(theoretical.map((point) => point.queries || 0)),
    ...(empirical.map((point) => point.queries || 0)),
    currentQuery || 0,
    collisionQuery || 0,
    expectedQuery || 0,
  );

  const theoreticalPath = buildPath(theoretical, xMax, width, height, padding);
  const empiricalPath = buildPath(empirical, xMax, width, height, padding);
  const yBase = height - padding.bottom;
  const xStart = padding.left;
  const xEnd = width - padding.right;

  const markerX = (value) => padding.left + (value / xMax) * (width - padding.left - padding.right);
  const markerY = (value) => height - padding.bottom - (value * (height - padding.top - padding.bottom));
  const currentProbability = currentQuery ? birthdayProbability(currentQuery, nBits) : 0;

  return (
    <div className="pa9-chart-card">
      <svg className="pa9-chart" viewBox={`0 0 ${width} ${height}`} role="img" aria-label="Birthday collision probability chart">
        <line x1={xStart} y1={yBase} x2={xEnd} y2={yBase} className="pa9-axis" />
        <line x1={xStart} y1={padding.top} x2={xStart} y2={yBase} className="pa9-axis" />

        {[0, 0.25, 0.5, 0.75, 1].map((tick) => {
          const y = markerY(tick);
          return (
            <g key={tick}>
              <line x1={xStart} y1={y} x2={xEnd} y2={y} className="pa9-grid" />
              <text x={xStart - 10} y={y + 4} className="pa9-axis-label" textAnchor="end">
                {tick.toFixed(2)}
              </text>
            </g>
          );
        })}

        {theoreticalPath && <path d={theoreticalPath} className="pa9-line pa9-line-theory" />}
        {empiricalPath && <path d={empiricalPath} className="pa9-line pa9-line-empirical" />}

        {expectedQuery ? (
          <>
            <line x1={markerX(expectedQuery)} y1={padding.top} x2={markerX(expectedQuery)} y2={yBase} className="pa9-marker pa9-marker-expected" />
            <text x={markerX(expectedQuery) + 6} y={padding.top + 14} className="pa9-marker-label">
              2^(n/2)
            </text>
          </>
        ) : null}

        {currentQuery ? (
          <>
            <line x1={markerX(currentQuery)} y1={padding.top} x2={markerX(currentQuery)} y2={yBase} className="pa9-marker pa9-marker-current" />
            <circle cx={markerX(currentQuery)} cy={markerY(Math.min(1, currentProbability))} r="5" className="pa9-dot-current" />
          </>
        ) : null}

        {collisionQuery ? (
          <circle
            cx={markerX(collisionQuery)}
            cy={markerY(Math.min(1, birthdayProbability(collisionQuery, nBits)))}
            r="5"
            className="pa9-dot-collision"
          />
        ) : null}

        <text x={(xStart + xEnd) / 2} y={height - 8} textAnchor="middle" className="pa9-axis-title">
          hashes computed
        </text>
        <text
          x={18}
          y={(padding.top + yBase) / 2}
          textAnchor="middle"
          className="pa9-axis-title"
          transform={`rotate(-90 18 ${(padding.top + yBase) / 2})`}
        >
          collision probability
        </text>
      </svg>

      <div className="pa9-legend">
        <span className="pa9-legend-item"><span className="pa9-swatch pa9-swatch-theory" /> Theory</span>
        {empirical.length > 0 && <span className="pa9-legend-item"><span className="pa9-swatch pa9-swatch-empirical" /> Empirical CDF</span>}
        <span className="pa9-legend-item"><span className="pa9-swatch pa9-swatch-current" /> Current search</span>
        <span className="pa9-legend-item"><span className="pa9-swatch pa9-swatch-expected" /> Expected marker</span>
      </div>
    </div>
  );
}

function birthdayProbability(queries, nBits) {
  if (!queries || !nBits) {
    return 0;
  }
  return 1 - Math.exp(-(queries * (queries - 1)) / (2 ** (nBits + 1)));
}

export function PA9LiveDemoPanel() {
  const [nBits, setNBits] = useState("12");
  const [displayCount, setDisplayCount] = useState(0);
  const { loading, data, error, run } = useAsync(api.pa9LiveDemo);

  useEffect(() => {
    if (!data) {
      return;
    }

    const finalCount = data.evaluations;
    const step = Math.max(1, Math.ceil(finalCount / 140));
    const timer = setInterval(() => {
      setDisplayCount((previous) => {
        const next = Math.min(finalCount, previous + step);
        if (next >= finalCount) {
          clearInterval(timer);
        }
        return next;
      });
    }, 35);

    return () => clearInterval(timer);
  }, [data]);

  const submit = () => run({ n_bits: Number(nBits) });
  const liveProbability = data ? birthdayProbability(displayCount, Number(nBits)) : 0;
  const collisionVisible = data && displayCount >= data.evaluations;

  return (
    <PanelCard
      title="Interactive Birthday Attack Demo"
      formula={"\\Pr[\\mathrm{collision\\ by\\ }q] \\approx 1 - e^{-q(q-1)/2^{n+1}}"}
      desc="Pick a truncation length, run the attack, and watch the counter climb until two different inputs land on the same n-bit hash value."
      fullWidth
      inputContent={(
        <>
          <Field label="Output bit-length">
            <SegControl
              value={nBits}
              onChange={setNBits}
              options={[
                { value: "8", label: "8-bit" },
                { value: "10", label: "10-bit" },
                { value: "12", label: "12-bit" },
                { value: "14", label: "14-bit" },
                { value: "16", label: "16-bit" },
              ]}
            />
          </Field>
          <button className="btn-primary" onClick={submit} disabled={loading}>
            {loading ? <><Spinner /> Preparing...</> : "Run Attack"}
          </button>
          <div className="pa9-callout">
            The backend returns a real collision instance, and the frontend animates the search so the counter and curve move together.
          </div>
        </>
      )}
      outputContent={(
        <ResultArea loading={loading} error={error} data={data}>
          {data && (
            <div className="result-structured">
              <div className="pa9-metric-grid">
                <div className="pa9-metric">
                  <span className="pa9-metric-label">hashes computed</span>
                  <span className="pa9-metric-value">{displayCount.toLocaleString()}</span>
                </div>
                <div className="pa9-metric">
                  <span className="pa9-metric-label">theory at q</span>
                  <span className="pa9-metric-value">{(liveProbability * 100).toFixed(1)}%</span>
                </div>
                <div className="pa9-metric">
                  <span className="pa9-metric-label">expected point</span>
                  <span className="pa9-metric-value">{formatNumber(data.expected_marker, 0)}</span>
                </div>
              </div>

              <ProbabilityChart
                theoretical={data.theoretical_curve}
                nBits={Number(nBits)}
                currentQuery={displayCount}
                collisionQuery={collisionVisible ? data.evaluations : null}
                expectedQuery={data.expected_marker}
              />

              <div className="result-row" style={{ flexWrap: "wrap", gap: 8 }}>
                <Badge variant={collisionVisible ? "pass" : "warn"}>
                  {collisionVisible ? "Collision Found" : "Searching"}
                </Badge>
                <Badge variant="info">{data.n_bits}-bit toy hash</Badge>
                <span className="result-label">final count: {data.evaluations}</span>
              </div>

              {collisionVisible && (
                <>
                  <div className="result-field">
                    <span className="result-field-label">Shared digest</span>
                    <code className="hex-output">{data.collision_digest_hex}</code>
                  </div>
                  <div className="result-field">
                    <span className="result-field-label">Input A</span>
                    <code className="hex-output">{data.input1_hex}</code>
                  </div>
                  <div className="result-field">
                    <span className="result-field-label">Input B</span>
                    <code className="hex-output">{data.input2_hex}</code>
                  </div>
                </>
              )}
            </div>
          )}
        </ResultArea>
      )}
    />
  );
}

export function PA9ComparePanel() {
  const [trials, setTrials] = useState(24);
  const { loading, data, error, run } = useAsync(api.pa9Compare);

  const submit = () => run({ trials: Number(trials) });

  return (
    <PanelCard
      title="Naive vs Floyd"
      formula={"\\text{time} \\approx 2^{n/2},\\quad \\text{space}_{\\mathrm{naive}} = O(k),\\quad \\text{space}_{\\mathrm{Floyd}} = O(1)"}
      desc="Runs both collision-finding strategies on the deliberately weak toy hash so you can compare evaluation counts against the birthday bound."
      fullWidth
      inputContent={(
        <>
          <Field label={`Independent trials: ${trials}`} hint="More trials smooth the averages but take a little longer.">
            <input
              type="range"
              min={4}
              max={60}
              step={4}
              value={trials}
              onChange={(event) => setTrials(Number(event.target.value))}
              className="range-slider"
              style={{ width: "100%" }}
            />
          </Field>
          <button className="btn-primary" onClick={submit} disabled={loading}>
            {loading ? <><Spinner /> Measuring...</> : "Compare Algorithms"}
          </button>
        </>
      )}
      outputContent={(
        <ResultArea loading={loading} error={error} data={data}>
          {data && (
            <div className="result-structured">
              <div className="result-row" style={{ flexWrap: "wrap", gap: 8 }}>
                <Badge variant="info">{data.trials} trials per n</Badge>
                <Badge variant="pass">Toy hash</Badge>
              </div>
              <table className="data-table">
                <thead>
                  <tr>
                    <th>n</th>
                    <th>Expected</th>
                    <th>Naive mean</th>
                    <th>Naive ratio</th>
                    <th>Floyd mean</th>
                    <th>Floyd ratio</th>
                  </tr>
                </thead>
                <tbody>
                  {data.results?.map((row) => (
                    <tr key={row.n_bits}>
                      <td><strong>{row.n_bits}</strong></td>
                      <td>{formatNumber(row.expected_work, 0)}</td>
                      <td>{formatNumber(row.naive.mean, 1)}</td>
                      <td>{formatNumber(row.naive.ratio_mean_to_bound, 2)}</td>
                      <td>{formatNumber(row.floyd.mean, 1)}</td>
                      <td>{formatNumber(row.floyd.ratio_mean_to_bound, 2)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              <div className="pa9-callout">
                The ratios should stay near a constant as n grows, which is the empirical fingerprint of the O(2^(n/2)) birthday bound.
              </div>
            </div>
          )}
        </ResultArea>
      )}
    />
  );
}

export function PA9DlpAttackPanel() {
  const [algorithm, setAlgorithm] = useState("naive");
  const { loading, data, error, run } = useAsync(api.pa9Attack);

  const submit = () => run({ hash_kind: "dlp", algorithm, n_bits: 16 });

  return (
    <PanelCard
      title="Attack Truncated PA8 DLP Hash"
      formula={"H_{16}(M) = H(M) \\bmod 2^{16}"}
      desc="This demonstrates the key security lesson: even a strong collision-resistant hash becomes easy to collide once you truncate its output to only 16 bits."
      fullWidth
      inputContent={(
        <>
          <Field label="Collision-finding algorithm">
            <SegControl
              value={algorithm}
              onChange={setAlgorithm}
              options={[
                { value: "naive", label: "Naive birthday" },
                { value: "floyd", label: "Floyd cycle" },
              ]}
            />
          </Field>
          <button className="btn-primary" onClick={submit} disabled={loading}>
            {loading ? <><Spinner /> Attacking...</> : "Attack 16-bit DLP Hash"}
          </button>
        </>
      )}
      outputContent={(
        <ResultArea loading={loading} error={error} data={data}>
          {data && (
            <div className="result-structured">
              <div className="result-row" style={{ flexWrap: "wrap", gap: 8 }}>
                <Badge variant="warn">PA8 truncated to 16 bits</Badge>
                <Badge variant="info">{data.algorithm}</Badge>
                <span className="result-label">{data.evaluations} evaluations</span>
              </div>
              <div className="result-field">
                <span className="result-field-label">Shared digest</span>
                <code className="hex-output">{data.collision_digest_hex}</code>
              </div>
              <div className="result-field">
                <span className="result-field-label">Colliding input A</span>
                <code className="hex-output">{data.input1_hex}</code>
              </div>
              <div className="result-field">
                <span className="result-field-label">Colliding input B</span>
                <code className="hex-output">{data.input2_hex}</code>
              </div>
              <div className="pa9-metric-grid">
                <div className="pa9-metric">
                  <span className="pa9-metric-label">expected 2^(n/2)</span>
                  <span className="pa9-metric-value">{formatNumber(data.expected_work, 0)}</span>
                </div>
                <div className="pa9-metric">
                  <span className="pa9-metric-label">evals / bound</span>
                  <span className="pa9-metric-value">{formatNumber(data.ratio_to_birthday_bound, 2)}</span>
                </div>
                <div className="pa9-metric">
                  <span className="pa9-metric-label">space</span>
                  <span className="pa9-metric-value">{data.space_complexity}</span>
                </div>
              </div>
            </div>
          )}
        </ResultArea>
      )}
    />
  );
}

export function PA9CurvePanel() {
  const [trials, setTrials] = useState(100);
  const [selectedBits, setSelectedBits] = useState(12);
  const { loading, data, error, run } = useAsync(api.pa9Curve);

  const submit = () => run({ trials: Number(trials) });
  const effectiveBits = data?.curves?.some((curve) => curve.n_bits === selectedBits)
    ? selectedBits
    : (data?.curves?.[0]?.n_bits ?? selectedBits);
  const selectedCurve = pickCurve(data?.curves, effectiveBits);

  return (
    <PanelCard
      title="Empirical Birthday Curve"
      formula={"1 - e^{-k(k-1)/2^{n+1}}"}
      desc="Runs many independent collision searches and overlays the empirical collision CDF against the standard birthday approximation."
      fullWidth
      inputContent={(
        <>
          <Field label={`Trials per n: ${trials}`}>
            <input
              type="range"
              min={20}
              max={120}
              step={10}
              value={trials}
              onChange={(event) => setTrials(Number(event.target.value))}
              className="range-slider"
              style={{ width: "100%" }}
            />
          </Field>
          <button className="btn-primary" onClick={submit} disabled={loading}>
            {loading ? <><Spinner /> Sampling...</> : "Run Curve Experiment"}
          </button>
          {data?.curves?.length ? (
            <Field label="Inspect one output size">
              <SegControl
                value={String(effectiveBits)}
                onChange={(value) => setSelectedBits(Number(value))}
                options={data.curves.map((curve) => ({
                  value: String(curve.n_bits),
                  label: `${curve.n_bits}-bit`,
                }))}
              />
            </Field>
          ) : null}
        </>
      )}
      outputContent={(
        <ResultArea loading={loading} error={error} data={data}>
          {selectedCurve && (
            <div className="result-structured">
              <div className="result-row" style={{ flexWrap: "wrap", gap: 8 }}>
                <Badge variant="info">{selectedCurve.n_bits}-bit toy hash</Badge>
                <Badge variant="pass">{data.trials} trials</Badge>
                <span className="result-label">mean: {formatNumber(selectedCurve.summary.mean, 1)} queries</span>
              </div>

              <ProbabilityChart
                theoretical={selectedCurve.theoretical_curve}
                empirical={selectedCurve.empirical_curve}
                nBits={selectedCurve.n_bits}
                expectedQuery={selectedCurve.expected_work}
              />

              <div className="pa9-metric-grid">
                <div className="pa9-metric">
                  <span className="pa9-metric-label">median</span>
                  <span className="pa9-metric-value">{formatNumber(selectedCurve.summary.median, 1)}</span>
                </div>
                <div className="pa9-metric">
                  <span className="pa9-metric-label">mean / bound</span>
                  <span className="pa9-metric-value">{formatNumber(selectedCurve.summary.ratio_mean_to_bound, 2)}</span>
                </div>
                <div className="pa9-metric">
                  <span className="pa9-metric-label">range</span>
                  <span className="pa9-metric-value">{selectedCurve.summary.min} to {selectedCurve.summary.max}</span>
                </div>
              </div>

              <div className="result-field">
                <span className="result-field-label">Sample trial counts</span>
                <div className="pa9-chip-row">
                  {selectedCurve.trial_counts.slice(0, 16).map((count, index) => (
                    <span key={`${count}-${index}`} className="pa9-chip">{count}</span>
                  ))}
                </div>
              </div>
            </div>
          )}
        </ResultArea>
      )}
    />
  );
}

export function PA9ContextPanel() {
  const [hashRate, setHashRate] = useState(1000000000);
  const { loading, data, error, run } = useAsync(api.pa9Context);

  const submit = () => run({ hash_rate_per_second: Number(hashRate) });

  return (
    <PanelCard
      title="MD5 / SHA-1 Context"
      formula={"\\text{attack time} = 2^{n/2} / R"}
      desc="Translates birthday complexity into wall-clock time so the cost difference between 128-bit and 160-bit outputs is easy to interpret."
      fullWidth
      inputContent={(
        <>
          <Field label="Hashes per second" hint="Use a modern throughput estimate such as 10^9 hashes/sec.">
            <input
              type="number"
              value={hashRate}
              onChange={(event) => setHashRate(event.target.value)}
              className="input"
            />
          </Field>
          <button className="btn-primary" onClick={submit} disabled={loading}>
            {loading ? <><Spinner /> Estimating...</> : "Compute Context"}
          </button>
        </>
      )}
      outputContent={(
        <ResultArea loading={loading} error={error} data={data}>
          {data && (
            <div className="result-structured">
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Hash</th>
                    <th>n</th>
                    <th>2^(n/2)</th>
                    <th>Seconds at R</th>
                    <th>Years at R</th>
                  </tr>
                </thead>
                <tbody>
                  {data.results?.map((row) => (
                    <tr key={row.algorithm}>
                      <td><strong>{row.algorithm}</strong></td>
                      <td>{row.output_bits}</td>
                      <td>{row.birthday_work_sci}</td>
                      <td>{row.seconds_at_rate_sci}</td>
                      <td>{row.years_at_rate_sci}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              <div className="pa9-callout">
                Each extra output bit doubles the collision-search cost. That is why moving from 128 bits to 160 bits is a massive jump in practical attack time.
              </div>
            </div>
          )}
        </ResultArea>
      )}
    />
  );
}
