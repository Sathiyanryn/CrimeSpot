import React, { useEffect, useState } from 'react'
import { MapContainer, TileLayer, Marker, Popup } from 'react-leaflet'
import 'leaflet/dist/leaflet.css'
import L from 'leaflet'
import API from '../services/api'
import { getToken, logout } from '../services/auth'
import { useNavigate } from 'react-router-dom'
import { io } from 'socket.io-client'

delete L.Icon.Default.prototype._getIconUrl
L.Icon.Default.mergeOptions({
  iconRetinaUrl: new URL('leaflet/dist/images/marker-icon-2x.png', import.meta.url).href,
  iconUrl: new URL('leaflet/dist/images/marker-icon.png', import.meta.url).href,
  shadowUrl: new URL('leaflet/dist/images/marker-shadow.png', import.meta.url).href,
})

const PatrolDashboard = () => {
  const [alerts, setAlerts] = useState([])
  const [crimes, setCrimes] = useState([])
  const [connected, setConnected] = useState(false)
  const [myLocation, setMyLocation] = useState(null)
  const navigate = useNavigate()

  // Fetch crimes
  const fetchCrimes = async () => {
    try {
      const res = await API.get('/api/crimes', {
        headers: { Authorization: `Bearer ${getToken()}` },
      })
      setCrimes(res.data)
    } catch (err) {
      console.error(err)
      if (err?.response?.status === 401) {
        logout()
        navigate('/login')
      }
    }
  }

  useEffect(() => { fetchCrimes() }, [])

  // Connect to Socket.IO
  useEffect(() => {
    const socket = io('http://127.0.0.1:5000', {
      transports: ['websocket'],
      auth: { token: getToken() },
    })

    socket.on('connect', () => {
      console.log('✅ Connected to Socket.IO server')
      setConnected(true)
    })

    socket.on('disconnect', () => {
      console.log('❌ Disconnected from Socket.IO server')
      setConnected(false)
    })

    socket.on('new_alert', (data) => {
      setAlerts((prev) => [data, ...prev])
      alert(`🚨 ${data.message} at ${data.location}`)
    })

    socket.on('crime_zone_alert', (data) => {
      setAlerts((prev) => [data, ...prev])
    })

    return () => socket.disconnect()
  }, [])

  const handleLogout = () => {
    logout()
    navigate('/login')
  }

  const handleUseMyLocation = () => {
    if (!navigator.geolocation) return alert('Geolocation not supported')
    navigator.geolocation.getCurrentPosition(
      (pos) => setMyLocation({ lat: pos.coords.latitude, lng: pos.coords.longitude }),
      (err) => alert('Unable to fetch location: ' + err.message),
      { enableHighAccuracy: true }
    )
  }

  return (
    <div className="flex flex-col h-screen">
      {/* Header */}
      <div className="bg-blue-700 text-white p-4 flex justify-between items-center">
        <h1 className="text-xl font-bold">🚓 Patrol Dashboard</h1>
        <div className="flex gap-3 items-center">
          <span>{connected ? '🟢 Connected' : '🔴 Disconnected'}</span>
          <button
            className="bg-yellow-500 px-3 py-1 rounded"
            onClick={handleUseMyLocation}
          >
            Use my location
          </button>
          <button
            className="bg-red-500 px-3 py-1 rounded"
            onClick={handleLogout}
          >
            Logout
          </button>
        </div>
      </div>

      {/* Main content */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 flex-1">
        {/* Map */}
        <div className="md:col-span-2 h-full bg-white rounded shadow overflow-hidden">
          <MapContainer center={[13.0827, 80.2707]} zoom={12} style={{ height: '100%', width: '100%' }}>
            <TileLayer url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png" />
            {crimes.map((crime, idx) =>
              crime.lat && crime.lng && (
                <Marker key={idx} position={[crime.lat, crime.lng]}>
                  <Popup>
                    <div className="font-bold">{crime.location}</div>
                    <div>{crime.type}</div>
                    <div className="text-xs">{crime.date}</div>
                  </Popup>
                </Marker>
              )
            )}
            {myLocation && (
              <Marker position={[myLocation.lat, myLocation.lng]}>
                <Popup>Your location</Popup>
              </Marker>
            )}
          </MapContainer>
        </div>

        {/* Alerts */}
        <div className="bg-gray-100 p-3 rounded shadow h-full overflow-y-auto">
          <h2 className="text-lg font-semibold mb-2">Incoming Alerts</h2>
          {alerts.length === 0 ? (
            <p className="text-gray-500">No alerts yet.</p>
          ) : (
            alerts.map((alert, idx) => (
              <div key={idx} className="bg-white p-2 mb-2 rounded shadow-sm">
                <p className="font-medium text-red-600">{alert.message}</p>
                <p className="text-sm text-gray-600">{alert.location}</p>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  )
}

export default PatrolDashboard
