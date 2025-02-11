// Set Mapbox access token
mapboxgl.accessToken = "pk.eyJ1Ijoic3ViaGFtcHJlZXQiLCJhIjoiY2toY2IwejF1MDdodzJxbWRuZHAweDV6aiJ9.Ys8MP5kVTk5P9V2TDvnuDg";

// Fetch wind speed data when the button is clicked
document.getElementById('fetchDataBtn').addEventListener('click', () => {
    const latitude = document.getElementById('latitude').value;
    const longitude = document.getElementById('longitude').value;

    if (!latitude || !longitude) {
        alert('Please enter both latitude and longitude');
        return;
    }

    // NASA Power API endpoint for daily wind speed (WS10M) data
    const apiUrl = `https://power.larc.nasa.gov/api/temporal/daily/point?parameters=WS10M&community=RE&longitude=${longitude}&latitude=${latitude}&start=20230101&end=20230115&format=JSON`;

    // Fetching the wind speed data
    fetch(apiUrl)
        .then(response => response.json())
        .then(data => {
            console.log(data); // For debugging: check the API response structure
            displayResult(data);
        })
        .catch(error => {
            console.error('Error fetching data:', error);
        });

    // Setup map with provided latitude and longitude
    setupMap([longitude, latitude]);
});

// Function to display wind speed results
function displayResult(data) {
    const resultDiv = document.getElementById('result');
    const windSpeedData = data.properties?.parameter?.WS10M; // Accessing the wind speed data

    if (windSpeedData) {
        resultDiv.innerHTML = `<h3>Wind Speed Data (m/s):</h3><pre>${JSON.stringify(windSpeedData, null, 2)}</pre>`;
    } else {
        resultDiv.innerHTML = 'No wind speed data available for this location.';
    }
}

// Get current location using geolocation
navigator.geolocation.getCurrentPosition(successLocation, errorLocation, {
    enableHighAccuracy: true
});

// Functions to handle geolocation success and error
function successLocation(position) {
    const coords = [position.coords.longitude, position.coords.latitude];
    console.log(`Longitude: ${coords[0]}, Latitude: ${coords[1]}`); // Log the latitude and longitude
    setupMap(coords);
}

function errorLocation() {
    const defaultCoords = [-2.24, 53.48];
    console.log(`Longitude: ${defaultCoords[0]}, Latitude: ${defaultCoords[1]}`); // Log the default latitude and longitude
    setupMap(defaultCoords);
}

// Function to setup the Mapbox map
function setupMap(center) {
    const map = new mapboxgl.Map({
        container: "map",
        style: "mapbox://styles/mapbox/streets-v11",
        center: center,
        zoom: 15
    });

    const nav = new mapboxgl.NavigationControl();
    map.addControl(nav);

    var directions = new MapboxDirections({
        accessToken: mapboxgl.accessToken
    });

    map.addControl(directions, "top-left");
}
