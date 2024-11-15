//main function
async function calculateEstimatedPrice(vehicle, pickup, drop, weightrange) {
    const vehicleType = getVehicleType(vehicle);

    let basePrice = 0;
    let distanceinfo = ""; //can be (inDelhiNCR/lessThan600Km/moreThan600Km)

    try {
        const [pickupLocation, dropLocation] = await Promise.all([getLocationDetails(pickup), getLocationDetails(drop)]);

        if (isInDelhiNCR(pickupLocation) && isInDelhiNCR(dropLocation)) {
            distanceinfo = "inDelhiNCR";
            basePrice = calculatePriceByWeight(distanceinfo, vehicleType, weightrange);
        } else {
            const distance = await calculateDistance(pickupLocation.geometry.location, dropLocation.geometry.location);
            console.log(distance)
            if (distance <= 600) {
                distanceinfo = "lessThan600Km";
                basePrice = calculatePriceByWeight(distanceinfo, vehicleType, weightrange);
            } else {
                distanceinfo = "moreThan600Km";
                basePrice = calculatePriceByWeight(distanceinfo, vehicleType, weightrange);
            }
        }
    } catch (error) {
        console.error("Error in calculating estimated price:", error);
    }

    return basePrice;
}

// identifing the vehicle type: frozen, chiller, dry from the vehicle object
function getVehicleType(vehicle) {
    return vehicle.vehicleType.toLowerCase();
}

// function to find the price per kg and price range based on the type of order
function calculatePriceByWeight(distanceinfo, vehicleType, weightrange) {
    const pricingDelhiNCR = {
        frozen: { "0-100": 20, "100-250": 15, "250-700": 6, "700-1000": 5, "1000+": 5 },
        chiller: { "0-100": 0, "100-250": 0, "250-700": 0, "700-1000": 0, "1000+": 0 },
        dry: { "0-100": 0, "100-250": 0, "250-700": 0, "700-1000": 0, "1000+": 0 },
    };
    const pricingLessThan600Km = {
        frozen: { "0-100": 45, "100-250": 40, "250-700": 35, "700-1000": 30, "1000+": 30 },
        chiller: { "0-100": 0, "100-250": 0, "250-700": 0, "700-1000": 0, "1000+": 0 },
        dry: { "0-100": 0, "100-250": 0, "250-700": 0, "700-1000": 0, "1000+": 0 },
    };
    const pricingMoreThan600Km = {
        frozen: { "0-100": 50, "100-250": 40, "250-700": 35, "700-1000": 25, "1000+": 20 },
        chiller: { "0-100": 0, "100-250": 0, "250-700": 0, "700-1000": 0, "1000+": 0 },
        dry: { "0-100": 0, "100-250": 0, "250-700": 0, "700-1000": 0, "1000+": 0 },
    };

    const minMaxWeights = {
        "0-100": [0, 100],
        "100-250": [100, 250],
        "250-700": [250, 700],
        "700-1000": [700, 1000],
        "1000+": [1000, 100000],
    };
    const [minWeight, maxWeight] = minMaxWeights[weightrange];

    let weightCategory = "";
    if (weightrange == "0-100") weightCategory = "0-100";
    else if (weightrange == "100-250") weightCategory = "100-250";
    else if (weightrange == "250-700") weightCategory = "250-700";
    else if (weightrange == "700-1000") weightCategory = "700-1000";
    else weightCategory = "1000+";

    let pricePerKg = 0;
    if (distanceinfo == "inDelhiNCR") {
        pricePerKg = pricingDelhiNCR[vehicleType][weightCategory];
    } else if (distanceinfo == "lessThan600Km") {
        pricePerKg = pricingLessThan600Km[vehicleType][weightCategory];
    } else if (distanceinfo == "moreThan600Km") {
        pricePerKg = pricingMoreThan600Km[vehicleType][weightCategory];
    } else {
        console.error("Error calculating price:");
    }

    const { minPrice, maxPrice } = estimatedPriceRange(pricePerKg, minWeight, maxWeight);

    return {
        pricePerKg,
        estimatedPriceRange: ` ₹ ${minPrice} - ${maxPrice}`,
    };
}

// function to find the estimated price range based on the weight range and price per kg
function estimatedPriceRange(pricePerKg, minWeight, maxWeight) {
    const minPrice = pricePerKg * minWeight;
    const maxPrice = pricePerKg * maxWeight;
    return {
        minPrice: minPrice,
        maxPrice: maxPrice,
    };
}

// Function to get location details
function getLocationDetails(location) {
    return new Promise((resolve, reject) => {
        const service = new google.maps.places.PlacesService(document.createElement("div"));
        service.textSearch({ query: location }, (results, status) => {
            if (status === google.maps.places.PlacesServiceStatus.OK && results.length > 0) {
                resolve(results[0]);
            } else {
                reject(`Error retrieving location for "${location}": ${status}`);
            }
        });
    });
}

// Check if location is in Delhi NCR
function isInDelhiNCR(location) {
    const delhiNCRBounds = {
        north: 28.8835,
        south: 28.4042,
        east: 77.354,
        west: 76.8355,
    };
    const { lat, lng } = location.geometry.location;
    return lat() <= delhiNCRBounds.north && lat() >= delhiNCRBounds.south && lng() <= delhiNCRBounds.east && lng() >= delhiNCRBounds.west;
}

// Calculate the distance between locations (returns Promise)
function calculateDistance(pickupLocation, dropLocation) {
    return new Promise((resolve, reject) => {
        const origin = new google.maps.LatLng(pickupLocation.lat(), pickupLocation.lng());
        const destination = new google.maps.LatLng(dropLocation.lat(), dropLocation.lng());

        const service = new google.maps.DistanceMatrixService();
        service.getDistanceMatrix(
            {
                origins: [origin],
                destinations: [destination],
                travelMode: "DRIVING",
            },
            (response, status) => {
                if (status === "OK") {
                    const distanceText = response.rows[0].elements[0].distance.text;
                    console.log(distanceText)
                    const distance = parseFloat(distanceText.replace(/,/g, "").replace(" km", ""));
                    console.log(distance)
                    resolve(distance);
                } else {
                    reject(`Error calculating distance: ${status}`);
                }
            }
        );
    });
}