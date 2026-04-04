// Global chart variable
let myChart = null;

// Get the sites dark mode to apply if needed to the chart
function getEchartsTheme() {
    return document.body.classList.contains('dark-mode') ? 'dark' : 'light';
}

// Initialize chart
function renderThreatConfidenceChart(){
    // Get the element to display the chart in
    const chartDom = document.getElementById('threat-confidence-chart');
    if(!chartDom) return;

    // Dispose of chart instance if it exists
    if(myChart){
        myChart.dispose();
    }

    // Initialize chart
    const theme = getEchartsTheme();
    myChart = echarts.init(chartDom, theme);

    // Define chart options
    const option = {
        title: {
            text: 'IOCs by Confidence Level',
            top: '3%'
        },
        tooltip: {
            trigger: 'item'
        },
        legend: {
            top: '12%',
            left: 'center',
        },
        series: [
            {
                name: 'IOCs with',
                type: 'pie',
                radius: ['40%', '70%'],
                center: ['50%', '60%'],
                avoidLabelOverlap: true,
                itemStyle: {
                    borderRadius: 10,
                    borderColor: '#fff',
                    borderWidth: 2
                },
                label: {
                    show: false,
                    position: 'center'
                },
                emphasis: {
                    label: {
                        show: true,
                        fontSize: 40,
                        fontWeight: 'bold'
                    }
                },
                labelLine: {
                    show: false
                },
                data: [
                    
                ]
            }
        ]
    };

    // Fetch data passed by Views.threat-confidence-chart-data function through urls.py
    fetch('/api/threat-confidence-chart-data/')
        .then(response => response.json())
        .then(data => {
            option.series[0].data = data;
            myChart.setOption(option);
        })
        .catch(error => {
            console.error('Error fetching chart data for threat confidence: ', error);
        });
}

// Call the function to initialize the chart
document.addEventListener('DOMContentLoaded', renderThreatConfidenceChart);

// Make the function globally accessible
window.renderThreatConfidenceChart = renderThreatConfidenceChart;