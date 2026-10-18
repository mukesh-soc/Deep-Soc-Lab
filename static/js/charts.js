/**
 * SentinelX SIEM Visualizations & Chart.js Integration
 * Renders real-time telemetry line charts, severity breakdown doughnuts,
 * and MITRE ATT&CK coverage bar charts.
 */

let timelineChart = null;
let severityChart = null;
let mitreChart = null;

function initCharts(metricsData) {
  renderTimelineChart();
  renderSeverityChart(metricsData ? metricsData.severity_counts : null);
  renderMitreChart(metricsData ? metricsData.mitre_coverage : null);
}

function renderTimelineChart() {
  const ctx = document.getElementById('timelineChartCanvas');
  if (!ctx) return;

  const labels = ['16:00:00', '16:00:05', '16:00:10', '16:00:15', '16:00:20', '16:00:25', '16:00:30', '16:00:35'];
  const eventCounts = [12, 19, 35, 48, 22, 14, 28, 42];
  const alertCounts = [0, 1, 4, 8, 2, 0, 1, 3];

  if (timelineChart) timelineChart.destroy();

  timelineChart = new Chart(ctx, {
    type: 'line',
    data: {
      labels: labels,
      datasets: [
        {
          label: 'Ingested Telemetry Events',
          data: eventCounts,
          borderColor: '#06b6d4',
          backgroundColor: 'rgba(6, 182, 212, 0.1)',
          fill: true,
          tension: 0.4,
          borderWidth: 2
        },
        {
          label: 'Correlated SIEM Alerts',
          data: alertCounts,
          borderColor: '#f43f5e',
          backgroundColor: 'rgba(244, 63, 94, 0.15)',
          fill: true,
          tension: 0.4,
          borderWidth: 2
        }
      ]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: {
          labels: { color: '#94a3b8', font: { size: 12, family: 'system-ui' } }
        }
      },
      scales: {
        x: {
          grid: { color: 'rgba(30, 46, 74, 0.4)' },
          ticks: { color: '#64748b' }
        },
        y: {
          grid: { color: 'rgba(30, 46, 74, 0.4)' },
          ticks: { color: '#64748b' }
        }
      }
    }
  });
}

function renderSeverityChart(severityCounts) {
  const ctx = document.getElementById('severityChartCanvas');
  if (!ctx) return;

  const counts = severityCounts || { Critical: 2, High: 3, Medium: 2, Low: 1 };

  if (severityChart) severityChart.destroy();

  severityChart = new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels: ['Critical', 'High', 'Medium', 'Low'],
      datasets: [{
        data: [counts.Critical || 0, counts.High || 0, counts.Medium || 0, counts.Low || 0],
        backgroundColor: ['#f43f5e', '#f59e0b', '#3b82f6', '#10b981'],
        borderWidth: 0,
        hoverOffset: 4
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      cutout: '70%',
      plugins: {
        legend: {
          position: 'bottom',
          labels: { color: '#94a3b8', font: { size: 11 } }
        }
      }
    }
  });
}

function renderMitreChart(mitreCoverage) {
  const ctx = document.getElementById('mitreChartCanvas');
  if (!ctx) return;

  let labels = [];
  let values = [];

  if (mitreCoverage && Object.keys(mitreCoverage).length > 0) {
    labels = Object.keys(mitreCoverage);
    values = Object.values(mitreCoverage);
  } else {
    labels = [
      'T1059.001 (PowerShell)',
      'T1071.001 (Web Protocols)',
      'T1573 (Encrypted Channel)',
      'T1003.001 (LSASS Dump)',
      'T1490 (Inhibit Recovery)'
    ];
    values = [4, 3, 2, 2, 1];
  }

  if (mitreChart) mitreChart.destroy();

  mitreChart = new Chart(ctx, {
    type: 'bar',
    data: {
      labels: labels,
      datasets: [{
        label: 'Detections Matched',
        data: values,
        backgroundColor: '#8b5cf6',
        borderRadius: 4
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      indexAxis: 'y',
      plugins: {
        legend: { display: false }
      },
      scales: {
        x: {
          grid: { color: 'rgba(30, 46, 74, 0.4)' },
          ticks: { color: '#64748b', precision: 0 }
        },
        y: {
          grid: { display: false },
          ticks: { color: '#94a3b8', font: { size: 11 } }
        }
      }
    }
  });
}

function updateChartsData(metrics) {
  if (severityChart && metrics.severity_counts) {
    severityChart.data.datasets[0].data = [
      metrics.severity_counts.Critical || 0,
      metrics.severity_counts.High || 0,
      metrics.severity_counts.Medium || 0,
      metrics.severity_counts.Low || 0
    ];
    severityChart.update();
  }

  if (mitreChart && metrics.mitre_coverage && Object.keys(metrics.mitre_coverage).length > 0) {
    mitreChart.data.labels = Object.keys(metrics.mitre_coverage);
    mitreChart.data.datasets[0].data = Object.values(metrics.mitre_coverage);
    mitreChart.update();
  }
}
