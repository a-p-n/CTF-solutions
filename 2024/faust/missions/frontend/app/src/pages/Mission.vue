<template>
	<h1>{{ mission.name }}</h1>
	<i>{{mission.short}}</i><br/>
	{{mission.data}}<br/>
	<hr/>
	Add a note:
	<form @submit="onSubmit">
		<v-text-field v-model="note"></v-text-field>
		<v-btn type="submit">Add Note</v-btn>
	</form>
	<gr/>
	<router-link :to="{name: '/'}">Back</router-link>
</template>

<script>
import axios from "axios";
export default {
	data: () => ({
		mission: [
		],
		note: ""
	}),
	methods: {
		onSubmit(event) {
			event.preventDefault();

			axios.post("/api/add_data", {
				data: this.note
			}, {
				withCredentials:true
			}).then(() => {
				//this.mission += this.note;
				this.note = "";
			}).catch(() => {
			});
		}
	},
	mounted () {
		const secret = localStorage.getItem("secret");
		axios.post("/api/get_data", {
			secret: secret
		}, {
			withCredentials:true
		}).then((data) => {
			this.mission = data.data
		}).catch(() => {
			// Handle the failed form submission.
		});
	}
}
</script>
