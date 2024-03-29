import { GoogleMap, MarkerF, useLoadScript, InfoWindowF } from "@react-google-maps/api";
import { Container, Button, Tab, Tabs } from '@mui/material';
import { useMemo, useState, useEffect } from "react";
import { Link, Navigate } from 'react-router-dom';
import http from "../../../http"
import '../../../bicycle.css'
import AdminPageTitle from "../../../components/AdminPageTitle";
import FormatListNumberedIcon from '@mui/icons-material/FormatListNumbered';

const libraries = ['geometry'];

function BicycleAdmin() {
    const [bicycle, setBicycle] = useState([]);
    const [loading, setLoading] = useState(true);
    const [currentLocation, setCurrentLocation] = useState(null);
    const [selectedMarker, setSelectedMarker] = useState(null);
    const [selectedSelf, setSelectedSelf] = useState(null);
    const [filter, setFilter] = useState('all');

    const { isLoaded } = useLoadScript({
        googleMapsApiKey: import.meta.env.VITE_GOOGLE_API_KEY,
        libraries: libraries,
    });

    const center = useMemo(() => ({ lat: 1.311, lng: 103.844 }), []);

    const handleGetBicycle = () => {
        http.get('/bicycle').then((res) => {
            if (res.status === 200) {
                setBicycle(res.data);
                setLoading(false);
            }
        });
    };

    const handleGetLocation = () => {
        if (navigator.geolocation) {
            navigator.geolocation.getCurrentPosition(
                (position) => {
                    setCurrentLocation({
                        lat: position.coords.latitude,
                        lng: position.coords.longitude,
                    });
                },
                (error) => {
                    console.error('Error getting user location:', error);
                }
            );
        } else {
            console.error('Geolocation is not supported by this browser.');
        }
    };

    const handleMarkerClick = (marker) => {
        if (marker.id === 0) {
            setSelectedSelf(marker);
            console.log('currentLocation:', currentLocation);
        } else {
            setSelectedMarker(marker);
            console.log('marker:', marker);
        }
    };

    const handleInfoWindowClose = () => {
        setSelectedMarker(null);
        setSelectedSelf(null);
    };

    const markers = useMemo(() => {
        // Filter the bicycles based on the selected filter
        let filteredBicycle = bicycle;
        if (filter === 'disabled') {
            filteredBicycle = bicycle.filter((bike) => bike.disabled);
        } else if (filter === 'registered') {
            filteredBicycle = bicycle.filter((bike) => bike.registered);
        } else if (filter === 'reports') {
            filteredBicycle = bicycle.filter((bike) => bike.reports > 0);
        }

        return filteredBicycle.map(({ id, bicycle_lat, bicycle_lng, reports }) => (
            <MarkerF key={id} position={{ lat: bicycle_lat, lng: bicycle_lng }} onClick={() => handleMarkerClick({ id, bicycle_lat, bicycle_lng, reports })} />
        ));
    }, [bicycle, filter]);

    const renderMap = () => {
        return (
            <GoogleMap
                mapContainerClassName="map-container"
                center={center}
                zoom={14}
                mapContainerStyle={{ width: '100%', marginBottom: '1rem' }}
                options={{
                    restriction: {
                        latLngBounds: bounds,
                        strictBounds: true,
                    },
                }}
            >
                {markers}
                {currentLocation && (
                    <MarkerF position={currentLocation} onClick={() => handleMarkerClick({ id: 0, bicycle_lat: currentLocation.lat, bicycle_lng: currentLocation.lng, reports: 0 })} />
                )}

                {selectedSelf && (
                    <InfoWindowF position={{ lat: currentLocation.lat, lng: currentLocation.lng }} onCloseClick={handleInfoWindowClose}>
                        <div>
                            <h3>Your Current Location</h3>
                            <p>Latitude: {currentLocation.lat}</p>
                            <p>Longitude: {currentLocation.lng}</p>
                        </div>
                    </InfoWindowF>
                )}

                {selectedMarker && (
                    <InfoWindowF position={{ lat: selectedMarker.bicycle_lat, lng: selectedMarker.bicycle_lng }} onCloseClick={handleInfoWindowClose}>
                        <div>
                            <h3>Bicycle Information</h3>
                            <p>Latitude: {selectedMarker.bicycle_lat}</p>
                            <p>Longitude: {selectedMarker.bicycle_lng}</p>
                            <p>Reports: {selectedMarker.reports}</p>
                            <Link to={`details/${selectedMarker.id}`}>View Details</Link>
                        </div>
                    </InfoWindowF>
                )}
            </GoogleMap>
        )
    }

    const bounds = {
        north: 1.493,
        south: 1.129,
        west: 103.557,
        east: 104.131,
    };

    const handleTabChange = (event, newValue) => {
        if (newValue === 'otherPage') {
            Navigate("/admin/bicycle/panel")
        } else {
            setFilter(newValue);
        }
    };

    useEffect(() => {
        document.title = 'EnviroGo - View Map';
        handleGetBicycle();
        handleGetLocation();
    }, []);

    return (
        <Container maxWidth="xl" sx={{ marginTop: '1rem' }}>
            <AdminPageTitle title="Bicycle Map" />
            <Button startIcon={<FormatListNumberedIcon />} LinkComponent={Link} variant="contained" color="primary" sx={{ marginBottom: '1rem' }} to="/admin/bicycle/view">
                View Bicycle List
            </Button>

            <Tabs
                value={filter}
                onChange={handleTabChange}
                variant="fullWidth"
                sx={{ marginBottom: '1rem' }}
            >
                <Tab label="All" value="all" />
                <Tab label="Disabled" value="disabled" />
                <Tab label="Registered" value="registered" />
                <Tab label="With Reports" value="reports" />
                <Tab label="Control Panel" value="otherPage" component={Link} to="/admin/bicycle/panel" />
            </Tabs>

            {!isLoaded ? (
                <h1>Loading...</h1>
            ) : (
                renderMap()
            )}
        </Container>
    );
};

export default BicycleAdmin;
