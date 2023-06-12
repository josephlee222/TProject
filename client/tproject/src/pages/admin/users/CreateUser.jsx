import React, { useState } from 'react'
import { Container, Typography, Card, CardContent, CardActions, Box, Stack, Checkbox, TextField, Grid, FormControlLabel, IconButton } from '@mui/material'
import LoadingButton from '@mui/lab/LoadingButton';
import ManageAccountsIcon from '@mui/icons-material/ManageAccounts';
import ArrowBackIcon from '@mui/icons-material/ArrowBack';
import AddIcon from '@mui/icons-material/Add';
import CardTitle from "../../../components/CardTitle";
import http from '../../../http'
import { useSnackbar } from 'notistack'
import { Form, useNavigate } from 'react-router-dom'
import * as Yup from "yup";
import { useFormik } from 'formik';

function CreateUser() {

    const [loading, setLoading] = useState(false);
    const { enqueueSnackbar } = useSnackbar();
    const navigate = useNavigate();

    const formik = useFormik({
        initialValues: {
            email: "",
            name: "",
            phone_number: "",
            is_admin: false,
        },
        validationSchema: Yup.object({
            email: Yup.string().email("Invalid email address").required("Email is required"),
            name: Yup.string().required("Name is required"),
            phone_number: Yup.string().optional(),
            is_admin: Yup.boolean().optional(),
        }),
        onSubmit: (data) => {
            setLoading(true);
            data.email = data.email.trim();
            data.name = data.name.trim();
            data.phone_number = data.phone_number.trim();
            if (data.is_admin == true) {
                data.account_type = 0;
            }
            if (data.phone_number == "") {
                delete data.phone_number;
            }
            
            delete data.is_admin;

            http.post("/admin/users", data).then((res) => {
                if (res.status === 200) {
                    enqueueSnackbar("User created successfully! E-mail has been sent to the user.", { variant: "success" });
                    navigate("/admin/users")
                } else {
                    enqueueSnackbar("User creation failed!.", { variant: "error" });
                    setLoading(false);
                }
            }).catch((err) => {
                enqueueSnackbar("User creation failed! " + err.response.data.message, { variant: "error" });
                setLoading(false);
            })
        }
    })

    return (
        <>
            <Container maxWidth="xl" sx={{ marginTop: "1rem" }}>
                <Box sx={{ display: "flex", alignItems: "center" }}>
                    <IconButton size="large" onClick={() => navigate(-1)} sx={{marginRight: "1rem"}}><ArrowBackIcon /></IconButton>
                    <Typography variant="h3" fontWeight={700} sx={{ marginY: ["1rem", "1rem", "2rem"], fontSize: ["2rem", "2rem", "3rem"] }}>Create User</Typography>
                </Box>
                <Card variant="outlined" sx={{ margin: "auto" }}>
                    <Box component="form" onSubmit={formik.handleSubmit}>
                        <CardContent>
                            <CardTitle title="Basic User Information" icon={<ManageAccountsIcon color="text.secondary" />} />
                            <TextField
                                fullWidth
                                id="email"
                                name="email"
                                label="Email"
                                variant="outlined"
                                value={formik.values.email}
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
                                        value={formik.values.name}
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
                                        value={formik.values.phone_number}
                                        onChange={formik.handleChange}
                                        error={formik.touched.phone_number && Boolean(formik.errors.phone_number)}
                                        helperText={formik.touched.phone_number && formik.errors.phone_number}
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
                                    onChange={formik.handleChange}
                                    error={formik.touched.is_admin && Boolean(formik.errors.is_admin)}
                                    helperText={formik.touched.is_admin && formik.errors.is_admin}
                                />
                            } />

                        </CardContent>
                        <CardActions>
                            <LoadingButton
                                variant="contained"
                                color="primary"
                                type="submit"
                                loading={loading}
                                loadingPosition="start"
                                startIcon={<AddIcon />}
                            >
                                Create User
                            </LoadingButton>
                        </CardActions>
                    </Box>
                </Card>
            </Container>
        </>
    )
}

export default CreateUser