// Global chart variable
let myChart = null;
let resizeObserver = null;

function getChartTextColor() {
    return document.body.classList.contains('dark-mode') ? '#f0f0f0' : '#1f2937';
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
    myChart = echarts.init(chartDom, null, { backgroundColor: 'transparent' });
    chartDom.style.backgroundColor = 'transparent';

    // Define chart options
    const option = {
        backgroundColor: 'transparent',
        title: {
            text: 'IOCs by Confidence Level',
            top: '2%',
            left: 'center',
            textStyle: {
                color: getChartTextColor()
            }
        },
        tooltip: {
            trigger: 'item'
        },
        legend: {
            bottom: '5%',
            left: 'center',
            type: 'scroll',
            orient: 'horizontal',
            textStyle: {
                overflow: 'break',
                color: getChartTextColor()
            }
        },
        series: [
            {
                name: 'IOCs with',
                type: 'pie',
                radius: ['35%', '65%'],
                center: ['50%', '45%'],
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

    // ResizeObserver to watch container size changes
    if(resizeObserver) {
        resizeObserver.disconnect();
    }
    resizeObserver = new ResizeObserver(() => {
        if(myChart && !myChart.isDisposed()){
            myChart.resize();
        }
    });
    resizeObserver.observe(chartDom);
}

// Call the function to initialize the chart
document.addEventListener('DOMContentLoaded', renderThreatConfidenceChart);

// Also handle window resize as fallback
window.addEventListener('resize', () => {
    if(myChart && !myChart.isDisposed()){
        myChart.resize();
    }
});

// Clean up on page unload
window.addEventListener('beforeunload', () => {
    if(resizeObserver){
        resizeObserver.disconnect();
    }
    if(myChart){
        myChart.dispose();
    }
});

// Make the function globally accessible
window.renderThreatConfidenceChart = renderThreatConfidenceChart;