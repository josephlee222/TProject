import React, { useState, useEffect } from 'react'
import { Box, Button, Container, Grid, TextField, Typography, CardContent, Card, Skeleton, IconButton, FormControlLabel, Checkbox, Stack, InputAdornment, Avatar, Tooltip, Dialog, DialogContent, DialogActions, DialogContentText, DialogTitle, Link, Input } from '@mui/material'
import LoadingButton from '@mui/lab/LoadingButton/LoadingButton';
import CardTitle from '../../../components/CardTitle';
import { useNavigate, useParams } from 'react-router-dom'
import ManageAccountsIcon from '@mui/icons-material/ManageAccounts';
import SaveIcon from '@mui/icons-material/Save';
import AccountBalanceWalletIcon from '@mui/icons-material/AccountBalanceWallet';
import CloseIcon from '@mui/icons-material/Close';
import FileUploadIcon from '@mui/icons-material/FileUpload';
import PublicIcon from '@mui/icons-material/Public';
import http from '../../../http'
import { useSnackbar } from 'notistack'
import * as Yup from "yup";
import { useFormik } from 'formik';
import ProfilePicture from '../../../components/ProfilePicture';
import AdminPageTitle from '../../../components/AdminPageTitle';
import md5 from "md5";

function EditUser() {
    const navigate = useNavigate();
    const [user, setUser] = useState(null);
    const { id } = useParams();
    const [loading, setLoading] = useState(false);
    const [loadingPicture, setLoadingPicture] = useState(false);
    const [changePictureDialog, setChangePictureDialog] = useState(false);
    const { enqueueSnackbar } = useSnackbar();

    const handleChangePictureDialogClose = () => {
        setChangePictureDialog(false);
    }

    const handleChangePictureDialogOpen = () => {
        setChangePictureDialog(true);
    }

    const handlePictureChange = (e) => {
        setLoadingPicture(true);
        console.log(e);
        const formData = new FormData();
        formData.append("profile_picture", e.target.files[0]);
        http.post("/admin/users/" + id + "/upload", formData, { headers: { "Content-Type": "multipart/form-data" } }).then((res) => {
            if (res.status === 200) {
                enqueueSnackbar("Profile picture updated successfully!", { variant: "success" });
                setUser(res.data);
                setLoadingPicture(false);
                handleChangePictureDialogClose();
            } else {
                enqueueSnackbar("Profile picture update failed!", { variant: "error" });
                setLoadingPicture(false);
                handleChangePictureDialogClose();
            }
        }).catch((err) => {
            enqueueSnackbar("Profile picture update failed! " + err.response.data.message, { variant: "error" });
            setLoadingPicture(false);
            handleChangePictureDialogClose();
        })
    }

    const handleGravatarChange = () => {
        setLoadingPicture(true);
        const data = {
            profile_picture_type: "gravatar"
        }
        http.put("/admin/users/" + id, data).then((res) => {
            if (res.status === 200) {
                enqueueSnackbar("Profile picture updated successfully!", { variant: "success" });
                setUser(res.data);
                setLoadingPicture(false);
                handleChangePictureDialogClose();
            } else {
                enqueueSnackbar("Profile picture update failed!", { variant: "error" });
                setLoadingPicture(false);
                handleChangePictureDialogClose();
            }
        }).catch((err) => {
            enqueueSnackbar("Profile picture update failed! " + err.response.data.message, { variant: "error" });
            setLoadingPicture(false);
            handleChangePictureDialogClose();
        })
    }

    const formik = useFormik({
        initialValues: {
            email: user ? user.email : "",
            name: user ? user.name : "",
            phone_number: user ? user.phone_number : "",
            is_admin: user ? user.account_type == 0 ? true : false : false,
            cash: user ? user.cash : 0,
            points: user ? user.points : 0,
            delivery_address: user ? user.delivery_address : "",
        },
        validationSchema: Yup.object({
            email: Yup.string().email("Invalid email address").required("Email is required"),
            name: Yup.string().required("Name is required"),
            phone_number: Yup.string().required(),
            is_admin: Yup.boolean().required(),
            cash: Yup.number().required("Cash balance is required"),
            points: Yup.number().required("Points balance is required")
        }),
        onSubmit: (data) => {
            setLoading(true);
            data.email = data.email.trim();
            data.name = data.name.trim();
            data.phone_number = data.phone_number.trim();
            if (data.is_admin == true) {
                data.account_type = 0;
            } else {
                data.account_type = 1;
            }

            if (data.phone_number == "") {
                delete data.phone_number;
            }

            delete data.is_admin;

            http.put("/admin/users/" + id, data).then((res) => {
                if (res.status === 200) {
                    enqueueSnackbar("User updated successfully!.", { variant: "success" });
                    navigate("/admin/users")
                } else {
                    enqueueSnackbar("User update failed!.", { variant: "error" });
                    setLoading(false);
                }
            }).catch((err) => {
                enqueueSnackbar("User update failed! " + err.response.data.message, { variant: "error" });
                setLoading(false);
            })
        },
        enableReinitialize: true
    })

    function getUser() {
        http.get("/admin/users/" + id).then((res) => {
            if (res.status === 200) {
                setUser(res.data);
            } else {
                enqueueSnackbar("User retrieval failed!.", { variant: "error" });
                setLoading(false);
                return navigate(-1);
            }
        }).catch((err) => {
            enqueueSnackbar("User retrieval failed! " + err.response.data.message, { variant: "error" });
            setLoading(false);
            return navigate(-1);
        })
    }

    useEffect(() => {
        getUser();
    }, [])

    return (
        <>
            <Container maxWidth="xl" sx={{ marginY: "1rem" }}>
                <AdminPageTitle backbutton title="Edit User" subtitle={"User: " + (user ? user.email : <Skeleton animation="wave" sx={{ display: "inline-block" }} variant="text" width={200} />)} />
                <Box component="form" onSubmit={formik.handleSubmit}>
                    <LoadingButton variant="contained" onClick={formik.handleSubmit} loading={loading} loadingPosition="start" startIcon={<SaveIcon />} sx={{ marginBottom: "1rem" }}>Save</LoadingButton>
                    <Stack spacing={2} direction="column" sx={{ marginBottom: "1rem" }}>
                        <Card>
                            <CardContent>
                                <CardTitle title="User Information" icon={<ManageAccountsIcon color="text.secondary" />} />
                                <Stack spacing={"2rem"} direction={["column", "column", "row"]}>
                                    <Box sx={{ display: ["flex", "flex", "initial"], justifyContent: 'center' }}>
                                        <Tooltip title="Change Profile Picture">
                                            <IconButton onClick={handleChangePictureDialogOpen}>
                                                {user && <ProfilePicture user={user} sx={{ width: "96px", height: "96px" }} />}
                                            </IconButton>
                                        </Tooltip>
                                    </Box>
                                    <Box flexGrow={1}>
                                        <TextField
                                            fullWidth
                                            id="email"
                                            name="email"
                                            label="E-mail Address"
                                            variant="outlined"
                                            value={formik.values.email || ""}
                                            onChange={formik.handleChange}
                                            error={formik.touched.email && Boolean(formik.errors.email)}
                                            helperText={formik.touched.email && formik.errors.email}
                                            sx={{ marginY: "1rem" }}
                                        />
                                        <Grid container spacing={2}>
                                            <Grid item xs={12} sm={6}>
                                                <TextField
                                                    fullWidth
                                                    id="name"
                                                    name="name"
                                                    label="Name"
                                                    variant="outlined"
                                                    value={formik.values.name || ""}
                                                    onChange={formik.handleChange}
                                                    error={formik.touched.name && Boolean(formik.errors.name)}
                                                    helperText={formik.touched.name && formik.errors.name}
                                                />
                                            </Grid>
                                            <Grid item xs={12} sm={6}>
                                                <TextField
                                                    fullWidth
                                                    id="phone_number"
                                                    name="phone_number"
                                                    label="Phone Number"
                                                    variant="outlined"
                                                    value={formik.values.phone_number || ""}
                                                    onChange={formik.handleChange}
                                                    error={formik.touched.phone_number && Boolean(formik.errors.phone_number)}
                                                    helperText={formik.touched.phone_number && formik.errors.phone_number}
                                                />
                                            </Grid>
                                            <Grid item xs={12}>
                                                <TextField
                                                    fullWidth
                                                    id="delivery_address"
                                                    name="delivery_address"
                                                    label="Delivery Address"
                                                    variant="outlined"
                                                    value={formik.values.delivery_address || ""}
                                                    onChange={formik.handleChange}
                                                    error={formik.touched.delivery_address && Boolean(formik.errors.delivery_address)}
                                                    helperText={formik.touched.delivery_address && formik.errors.delivery_address}
                                                />
                                            </Grid>
                                        </Grid>
                                        <FormControlLabel label="Is Admin" control={
                                            <Checkbox
                                                id="is_admin"
                                                name="is_admin"
                                                label="Is Admin"
                                                variant="outlined"
                                                value={formik.values.is_admin}
                                                checked={formik.values.is_admin}
                                                onChange={formik.handleChange}
                                                error={formik.touched.is_admin && Boolean(formik.errors.is_admin)}
                                                helperText={formik.touched.is_admin && formik.errors.is_admin}
                                            />
                                        } />
                                    </Box>
                                </Stack>

                            </CardContent>
                        </Card>
                        <Card sx={{ margin: "auto" }}>
                            <CardContent>
                                <CardTitle title="Wallet Information" icon={<AccountBalanceWalletIcon color="text.secondary" />} />
                                <Grid container spacing={2} marginTop={1}>
                                    <Grid item xs={12} sm={6}>
                                        <TextField
                                            fullWidth
                                            id="cash"
                                            name="cash"
                                            label="Cash Balance"
                                            variant="outlined"
                                            type='number'
                                            inputProps={{
                                                step: 0.01,
                                                min: 0,
                                                startAdornment: <InputAdornment position="start">S$</InputAdornment>,
                                            }}
                                            value={formik.values.cash || ""}
                                            onChange={formik.handleChange}
                                            error={formik.touched.cash && Boolean(formik.errors.cash)}
                                            helperText={formik.touched.cash && formik.errors.cash}
                                        />
                                    </Grid>
                                    <Grid item xs={12} sm={6}>
                                        <TextField
                                            fullWidth
                                            id="points"
                                            name="points"
                                            label="GreenMiles Balance"
                                            variant="outlined"
                                            type='number'
                                            inputProps={{
                                                step: 1,
                                                min: 0,
                                                endAdornment: <InputAdornment position="end">points</InputAdornment>,
                                            }}
                                            value={formik.values.points || ""}
                                            onChange={formik.handleChange}
                                            error={formik.touched.points && Boolean(formik.errors.points)}
                                            helperText={formik.touched.points && formik.errors.points}
                                        />
                                    </Grid>
                                </Grid>
                            </CardContent>
                        </Card>
                    </Stack>

                </Box>
            </Container>
            <Dialog open={changePictureDialog} onClose={handleChangePictureDialogClose}>
                <DialogTitle>Change Profile Picture</DialogTitle>
                <Box component="form">
                    <DialogContent sx={{ paddingTop: 0 }}>
                        <DialogContentText>
                            You are currently using a {user ? user.profile_picture_type === "gravatar" ? "Gravatar" : "local" : "unknown"} profile picture.
                            <br /><br />
                            You can select a new profile picture from your computer or from Gravatar. To set a new profile picture from your computer, click on the "Choose File" button below. To set a new profile picture from Gravatar, click on the "Use Gravatar" button below.
                            <br /><br />
                            For information on how to set a profile picture on Gravatar, please visit <Link href="https://en.gravatar.com/support/">https://en.gravatar.com/support/</Link>.
                        </DialogContentText>
                    </DialogContent>
                    <DialogActions>
                        <Stack direction={["column", "row"]} spacing={1}>
                            <Button style={{ justifyContent: "flex-end" }} onClick={handleChangePictureDialogClose} startIcon={<CloseIcon />}>Cancel</Button>
                            <LoadingButton style={{ justifyContent: "flex-end" }} loadingPosition="start" loading={loadingPicture} variant="text" color="primary" startIcon={<PublicIcon />} onClick={handleGravatarChange}>Use Gravatar</LoadingButton>
                            <LoadingButton style={{ justifyContent: "flex-end" }} loadingPosition="start" loading={loadingPicture} variant="text" color="primary" startIcon={<FileUploadIcon />} component="label">Upload Image<input type='file' onChange={handlePictureChange} hidden /></LoadingButton>
                        </Stack>
                    </DialogActions>
                </Box>
            </Dialog>
        </>
    )
}

export default EditUser